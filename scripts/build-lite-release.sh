#!/usr/bin/env bash
#
# 构建 Android + macOS 的 arm64 Lite 正式包（本机打包用，签名与 CI 一致：macOS adhoc、APK 用 android/app/keystore.jks）。
#
#   scripts/build-lite-release.sh              # stable，两个平台
#   scripts/build-lite-release.sh --env pre     # 预发布通道
#   scripts/build-lite-release.sh --skip-macos  # 只打 Android
#   scripts/build-lite-release.sh --no-clean    # 保留 build/，跳过 flutter clean 与 Rust 预热
#   scripts/build-lite-release.sh --check       # 只解析工具链并校验已有产物，不构建
#
# 工具链可以用环境变量覆盖：FLUTTER_HOME、JAVA_HOME、ANDROID_NDK、ANDROID_SDK_ROOT。
# 具体命令与踩坑记录见 docs/build-macos.md §3、§5。
#
# 兼容 macOS 自带 bash 3.2：不要在这里用关联数组或 `declare -A`。

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ENV_NAME=stable
DO_MACOS=1
DO_ANDROID=1
DO_CLEAN=1
CHECK_ONLY=0

log() { printf '==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
用法: scripts/build-lite-release.sh [选项]

  --env pre|stable   打包通道，默认 stable
  --skip-macos       只打 Android
  --skip-android     只打 macOS
  --no-clean         保留 build/，跳过 flutter clean 与 Rust 预热
  --check            只校验 dist/ 里已有的产物，不构建
  -h, --help         显示本说明
EOF
}

# dmg 挂载点在异常退出时也要清理。
MOUNT_POINT=""
cleanup_mount() {
  [ -n "$MOUNT_POINT" ] || return 0
  hdiutil detach "$MOUNT_POINT" >/dev/null 2>&1 || true
  rm -rf "$MOUNT_POINT"
  MOUNT_POINT=""
}
trap cleanup_mount EXIT

while [ $# -gt 0 ]; do
  case "$1" in
    --env) ENV_NAME="${2:-}"; [ -n "$ENV_NAME" ] || die "--env 需要一个值（pre 或 stable）"; shift 2 ;;
    --env=*) ENV_NAME="${1#*=}"; shift ;;
    --skip-macos) DO_MACOS=0; shift ;;
    --skip-android) DO_ANDROID=0; shift ;;
    --no-clean) DO_CLEAN=0; shift ;;
    --check) CHECK_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "未知参数 $1（--help 看用法）" ;;
  esac
done

case "$ENV_NAME" in
  pre|stable) ;;
  *) die "--env 只支持 pre 或 stable，收到 $ENV_NAME" ;;
esac

[ "$DO_MACOS" = 1 ] || [ "$DO_ANDROID" = 1 ] || die "--skip-macos 与 --skip-android 不能同时给"

# ---------------------------------------------------------------- 工具链解析

java_major() {
  "$1/bin/java" -version 2>&1 | sed -n 's/.*version "\([0-9]*\).*/\1/p' | head -1
}

resolve_toolchain() {
  FLUTTER_BIN="${FLUTTER_HOME:-$HOME/fvm/versions/3.47.7}/bin/flutter"
  if [ ! -x "$FLUTTER_BIN" ]; then
    FLUTTER_BIN="$(command -v flutter || true)"
    [ -n "$FLUTTER_BIN" ] ||
      die "找不到 Flutter SDK：设置 FLUTTER_HOME 指向 3.47.x（3.44.9 的 Dart 解不了 freezed 4，见文档 §3.1）"
  fi
  FLUTTER_HOME_RESOLVED="$(cd "$(dirname "$FLUTTER_BIN")/.." && pwd)"
  FLUTTER_VER="$("$FLUTTER_BIN" --version 2>/dev/null | sed -n 's/^Flutter \([0-9.]*\).*/\1/p' | head -1)"

  JAVA_HOME_RESOLVED=""
  for candidate in "${JAVA_HOME:-}" "$HOME/.sdkman/candidates/java/17.0.20-tem" "$(/usr/libexec/java_home -v 17 2>/dev/null || true)"; do
    [ -n "$candidate" ] || continue
    [ -x "$candidate/bin/java" ] || continue
    major="$(java_major "$candidate")"
    [ -n "$major" ] || continue
    if [ "$major" -ge 17 ]; then JAVA_HOME_RESOLVED="$candidate"; break; fi
  done
  [ -n "$JAVA_HOME_RESOLVED" ] ||
    die "找不到 JDK 17+（AGP 9 / Gradle 9.3 要求）：设置 JAVA_HOME"

  ANDROID_NDK_RESOLVED="${ANDROID_NDK:-}"
  if [ ! -d "$ANDROID_NDK_RESOLVED" ]; then
    ANDROID_NDK_RESOLVED=""
    for sdk in "${ANDROID_SDK_ROOT:-}" "${ANDROID_HOME:-}" /opt/homebrew/share/android-commandlinetools "$HOME/Library/Android/sdk"; do
      [ -n "$sdk" ] && [ -d "$sdk/ndk" ] || continue
      # 词法排序对 2x/3x 的 NDK 版本号足够，BSD sort 没有 -V。
      ANDROID_NDK_RESOLVED="$(ls -d "$sdk"/ndk/*/ 2>/dev/null | sed 's:/$::' | sort | tail -1)"
      [ -n "$ANDROID_NDK_RESOLVED" ] && break
    done
  fi
  [ -n "$ANDROID_NDK_RESOLVED" ] && [ -d "$ANDROID_NDK_RESOLVED" ] ||
    die "找不到 Android NDK：设置 ANDROID_NDK（CI 用 28.2.13676358）"

  export JAVA_HOME="$JAVA_HOME_RESOLVED"
  export ANDROID_NDK="$ANDROID_NDK_RESOLVED"
  export PATH="$FLUTTER_HOME_RESOLVED/bin:$HOME/.pub-cache/bin:$JAVA_HOME/bin:$PATH"
}

print_summary() {
  log "仓库      $ROOT"
  log "提交      $(git rev-parse --short HEAD) $(git log -1 --format=%s)"
  if [ -n "$(git status --porcelain)" ]; then
    log "注意      工作树有未提交改动，产物会包含它们"
  fi
  log "Flutter   $FLUTTER_VER（$FLUTTER_HOME_RESOLVED）"
  log "Java      $JAVA_HOME_RESOLVED"
  log "NDK       $ANDROID_NDK"
  log "目标      arm64 / lite / $ENV_NAME"
}

# 绕开 Cargokit 在 Xcode 并行构建下的 E0463（共享中间目录的陈旧指纹），见文档 §3.4。
warm_rust() {
  local target_dir=build/macos/Build/Intermediates.noindex/Pods.build/Release/code_forge.build
  local runner="cargo"
  command -v rustup >/dev/null 2>&1 && runner="rustup run stable cargo"
  log "预热 code_forge Rust 产物"
  rm -rf "$target_dir"
  $runner build \
    --manifest-path plugins/code_forge/rust/Cargo.toml \
    -p code_forge --release \
    --target aarch64-apple-darwin \
    --target-dir "$target_dir" >/dev/null
}

build_platform() {
  local platform="$1"
  log "构建 $platform（arm64 / lite / $ENV_NAME）"
  dart setup.dart "$platform" --arch arm64 --env "$ENV_NAME" --lite
}

# ---------------------------------------------------------------- 产物校验

build_tools_bin() {
  local sdk latest
  for sdk in "/opt/homebrew/share/android-commandlinetools" "${ANDROID_SDK_ROOT:-}" "${ANDROID_HOME:-}" "$HOME/Library/Android/sdk"; do
    [ -n "$sdk" ] && [ -d "$sdk/build-tools" ] || continue
    latest="$(ls -d "$sdk"/build-tools/*/ 2>/dev/null | sed 's:/$::' | sort | tail -1)"
    [ -n "$latest" ] && { echo "$latest"; return; }
  done
  return 1
}

verify_android() {
  local apk="dist/$APP_NAME-$APP_VERSION-android-lite-arm64-v8a.apk" bt badging native
  [ -f "$apk" ] || die "缺少产物 $apk"
  bt="$(build_tools_bin)" || die "找不到 Android build-tools（apksigner/aapt2）"

  badging="$("$bt/aapt2" dump badging "$apk" 2>/dev/null)"
  native="$(printf '%s\n' "$badging" | sed -n "s/^native-code: '\(.*\)'$/\1/p")"
  [ "$native" = "arm64-v8a" ] || die "$apk 的 native-code 是 '$native'，不是只有 arm64-v8a"

  log "APK       $(printf '%s\n' "$badging" | sed -n "1s/^package: name='\([^']*\)'.*/\1/p") \
$(printf '%s\n' "$badging" | sed -n "1s/.* versionName='\([^']*\)'.*/\1/p") \
($(printf '%s\n' "$badging" | sed -n "1s/.* versionCode='\([^']*\)'.*/\1/p")) / $native"
  log "APK 签名  $("$bt/apksigner" verify --print-certs "$apk" 2>/dev/null | sed -n 's/^Signer #1 certificate DN: //p')"
  log "APK 大小  $(du -h "$apk" | cut -f1)"
  log "APK sha256 $(shasum -a 256 "$apk" | cut -d' ' -f1)"
}

verify_macos() {
  local dmg="dist/$APP_NAME-$APP_VERSION-macos-arm64-lite.dmg" app arch
  [ -f "$dmg" ] || die "缺少产物 $dmg"
  MOUNT_POINT="$(mktemp -d)"
  # hdiutil 在 macOS 27 上会打一条 deprecation 警告到 stderr，这里只保留真正的失败。
  hdiutil attach -nobrowse -readonly -mountpoint "$MOUNT_POINT" "$dmg" >/dev/null 2>&1 ||
    die "挂载 $dmg 失败"
  app="$MOUNT_POINT/$APP_NAME.app"
  [ -d "$app" ] || die "$dmg 里没有 $APP_NAME.app"

  arch="$(lipo -info "$app/Contents/MacOS/$APP_NAME" | sed 's/.*: //')"
  case "$arch" in
    *arm64*) ;;
    *) die "$dmg 里的主程序架构是 $arch，不是 arm64" ;;
  esac

  log "DMG 主程序  $arch / $(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$app/Contents/Info.plist")"
  log "DMG 签名  $(codesign -dv --verbose=2 "$app" 2>&1 | sed -n 's/^Signature=//p')"
  log "DMG 大小  $(du -h "$dmg" | cut -f1)"
  log "DMG sha256 $(shasum -a 256 "$dmg" | cut -d' ' -f1)"

  cleanup_mount
}

# ---------------------------------------------------------------- 主流程

APP_VERSION="$(sed -n 's/^version: *\([0-9][0-9.]*\)+.*/\1/p' pubspec.yaml | head -1)"
[ -n "$APP_VERSION" ] || die "无法从 pubspec.yaml 读出 version"
# 与 setup.dart 的 Build.appName 一致，产物文件名由它决定。
APP_NAME="Bettbox"

resolve_toolchain
print_summary

LOG_DIR="dist/build-logs"
mkdir -p "$LOG_DIR"
STAMP="$(date +%Y%m%d-%H%M%S)"

if [ "$CHECK_ONLY" = 1 ]; then
  [ "$DO_MACOS" = 0 ] || verify_macos
  [ "$DO_ANDROID" = 0 ] || verify_android
  exit 0
fi

if [ "$DO_CLEAN" = 1 ]; then
  # 必须 clean：否则 build/app/outputs/flutter-apk/app-release.apk 里的旧通用包会被
  # setup.dart 复制成 lite 产物，体积和内容都是上一次的。
  log "flutter clean"
  "$FLUTTER_BIN" clean >/dev/null
  log "flutter pub get"
  "$FLUTTER_BIN" pub get >/dev/null
  # managed.js 的 @version 会在每次打包时自增，这里不去动它；提交时随包一起带上。
fi

if [ "$DO_MACOS" = 1 ] && [ "$DO_CLEAN" = 1 ]; then
  warm_rust
fi

if [ "$DO_MACOS" = 1 ]; then
  build_platform macos 2>&1 | tee "$LOG_DIR/macos-$STAMP.log"
  verify_macos
fi

if [ "$DO_ANDROID" = 1 ]; then
  build_platform android 2>&1 | tee "$LOG_DIR/android-$STAMP.log"
  verify_android
fi

log "完成，产物在 dist/，构建日志在 $LOG_DIR/"
