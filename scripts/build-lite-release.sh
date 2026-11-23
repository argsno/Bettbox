#!/usr/bin/env bash
#
# 构建 Android + macOS 的 arm64 Lite 正式包（本机打包用，签名与 CI 一致：macOS adhoc、APK 用 android/app/keystore.jks）。
#
#   scripts/build-lite-release.sh              # stable，两个平台
#   scripts/build-lite-release.sh --env pre     # 预发布通道
#   scripts/build-lite-release.sh --skip-macos  # 只打 Android
#   scripts/build-lite-release.sh --no-clean    # 保留 build/，跳过 flutter clean
#   scripts/build-lite-release.sh --check       # 只解析工具链并校验已有产物，不构建
#   scripts/build-lite-release.sh --install     # 校验通过后把 .app 装进 /Applications
#
# 工具链可以用环境变量覆盖：FLUTTER_HOME、JAVA_HOME、ANDROID_NDK、ANDROID_SDK_ROOT。
# 未设置 FLUTTER_HOME 时按仓库 .fvmrc 的版本取 $HOME/fvm/versions/<ver>，再退回 PATH 里的 flutter。
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
DO_INSTALL=0

log() { printf '==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
用法: scripts/build-lite-release.sh [选项]

  --env pre|stable   打包通道，默认 stable
  --skip-macos       只打 Android
  --skip-android     只打 macOS
  --no-clean         保留 build/，跳过 flutter clean
  --check            只校验 dist/ 里已有的产物，不构建
  --install           把刚校验过的 .app 装进 /Applications；配 --check 可只装不构建
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
    --install) DO_INSTALL=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "未知参数 $1（--help 看用法）" ;;
  esac
done

case "$ENV_NAME" in
  pre|stable) ;;
  *) die "--env 只支持 pre 或 stable，收到 $ENV_NAME" ;;
esac

[ "$DO_MACOS" = 1 ] || [ "$DO_ANDROID" = 1 ] || die "--skip-macos 与 --skip-android 不能同时给"
[ "$DO_INSTALL" = 0 ] || [ "$DO_MACOS" = 1 ] || die "--install 依赖 macOS 产物，不能配 --skip-macos"

# ---------------------------------------------------------------- 工具链解析

java_major() {
  "$1/bin/java" -version 2>&1 | sed -n 's/.*version "\([0-9]*\).*/\1/p' | head -1
}

# 优先级：FLUTTER_HOME → 仓库 .fvmrc 的版本 → PATH 里的 flutter；不做版本硬编码兜底。
resolve_flutter() {
  local ver
  if [ -n "${FLUTTER_HOME:-}" ]; then
    FLUTTER_BIN="$FLUTTER_HOME/bin/flutter"
    [ -x "$FLUTTER_BIN" ] ||
      die "FLUTTER_HOME=$FLUTTER_HOME，但 $FLUTTER_BIN 不存在或不可执行"
    return
  fi
  if [ -f "$ROOT/.fvmrc" ]; then
    ver="$(sed -n 's/.*"flutter"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$ROOT/.fvmrc" | head -1)"
    [ -n "$ver" ] || die "$ROOT/.fvmrc 里读不出 flutter 版本号"
    FLUTTER_BIN="$HOME/fvm/versions/$ver/bin/flutter"
    [ -x "$FLUTTER_BIN" ] ||
      die ".fvmrc 要求 Flutter $ver，但 $FLUTTER_BIN 不存在：先 fvm install $ver，或设置 FLUTTER_HOME"
    return
  fi
  FLUTTER_BIN="$(command -v flutter || true)"
  [ -n "$FLUTTER_BIN" ] ||
    die "找不到 Flutter SDK：未设置 FLUTTER_HOME，$ROOT/.fvmrc 不存在，PATH 里也没有 flutter"
}

# Flutter 持久化的 jdk-dir 优先于 JAVA_HOME 供 AGP 使用，必须单独校验，否则 lint 会崩在旧 JDK 上。
check_flutter_jdk_dir() {
  local jdk_dir major
  jdk_dir="$("$FLUTTER_BIN" config --list 2>/dev/null |
    sed -n 's/^ *jdk-dir: *\(.*[^ ]\) *$/\1/p' | head -1)"
  case "$jdk_dir" in
    ''|'(Not set)'|'Not set') return 0 ;;
  esac
  [ -x "$jdk_dir/bin/java" ] ||
    die "flutter config 的 jdk-dir=$jdk_dir 不是有效 JDK：flutter config --jdk-dir=<JDK 21 路径>"
  major="$(java_major "$jdk_dir")"
  [ -n "$major" ] ||
    die "读不出 flutter config 的 jdk-dir=$jdk_dir 的 Java 版本：flutter config --jdk-dir=<JDK 21 路径>"
  [ "$major" -ge 21 ] ||
    die "flutter config 的 jdk-dir 是 Java $major（$jdk_dir），AGP 9.3.1 的 lint 需要 21+；它覆盖 JAVA_HOME，改它：flutter config --jdk-dir=$JAVA_HOME_RESOLVED"
}

resolve_toolchain() {
  local candidate major
  resolve_flutter
  FLUTTER_HOME_RESOLVED="$(cd "$(dirname "$FLUTTER_BIN")/.." && pwd)"
  FLUTTER_VER="$("$FLUTTER_BIN" --version 2>/dev/null | sed -n 's/^Flutter \([0-9.]*\).*/\1/p' | head -1)"

  JAVA_HOME_RESOLVED=""
  for candidate in "${JAVA_HOME:-}" "$(/usr/libexec/java_home -v 21 2>/dev/null || true)" "$HOME"/.sdkman/candidates/java/21*/; do
    candidate="${candidate%/}"
    [ -n "$candidate" ] || continue
    [ -x "$candidate/bin/java" ] || continue
    major="$(java_major "$candidate")"
    [ -n "$major" ] || continue
    if [ "$major" -ge 21 ]; then JAVA_HOME_RESOLVED="$candidate"; break; fi
  done
  [ -n "$JAVA_HOME_RESOLVED" ] ||
    die "找不到 JDK 21+（AGP 9.3.1 的 lint 依赖 Java 21 API）：设置 JAVA_HOME"
  check_flutter_jdk_dir

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

build_platform() {
  local platform="$1"
  log "构建 $platform（arm64 / lite / $ENV_NAME）"
  dart setup.dart "$platform" --arch arm64 --env "$ENV_NAME"
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
  local apk="dist/$APP_NAME-$APP_VERSION-android-arm64-v8a.apk" bt badging native
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
  local dmg="dist/$APP_NAME-$APP_VERSION-macos-arm64.dmg" app arch
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

# 把刚校验过的 dmg 里的 .app 装进 /Applications。运行中的实例先发 quit Apple event，
# 装完如果之前在跑就重新拉起，尽量不打断使用状态。
install_macos() {
  local dmg="dist/$APP_NAME-$APP_VERSION-macos-arm64.dmg"
  local dest="/Applications/$APP_NAME.app"
  local was_running=0 i
  [ -f "$dmg" ] || die "缺少产物 $dmg"

  if pgrep -x "$APP_NAME" >/dev/null 2>&1; then
    was_running=1
    log "Bettbox 正在运行，先请求退出"
    osascript -e "quit app \"$APP_NAME\"" >/dev/null 2>&1 || true
    i=0
    while pgrep -x "$APP_NAME" >/dev/null 2>&1; do
      i=$((i + 1))
      [ "$i" -le 10 ] || die "Bettbox 10 秒内没退干净，手动退出后跑 scripts/build-lite-release.sh --check --install"
      sleep 1
    done
  fi

  MOUNT_POINT="$(mktemp -d)"
  hdiutil attach -nobrowse -readonly -mountpoint "$MOUNT_POINT" "$dmg" >/dev/null 2>&1 ||
    die "挂载 $dmg 失败"
  rm -rf "$dest"
  ditto "$MOUNT_POINT/$APP_NAME.app" "$dest" || die "装进 $dest 失败，dmg 仍在 dist/ 里可手动装"
  cleanup_mount

  log "已安装  $dest"
  if [ "$was_running" = 1 ]; then
    log "重新拉起 Bettbox"
    open -a "$dest"
  fi
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
  if [ "$DO_MACOS" = 1 ]; then
    verify_macos
    if [ "$DO_INSTALL" = 1 ]; then install_macos; fi
  fi
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

if [ "$DO_MACOS" = 1 ]; then
  build_platform macos 2>&1 | tee "$LOG_DIR/macos-$STAMP.log"
  verify_macos
  if [ "$DO_INSTALL" = 1 ]; then install_macos; fi
fi

if [ "$DO_ANDROID" = 1 ]; then
  build_platform android 2>&1 | tee "$LOG_DIR/android-$STAMP.log"
  verify_android
fi

log "完成，产物在 dist/，构建日志在 $LOG_DIR/"
