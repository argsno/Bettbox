import 'package:bett_box/enum/enum.dart';
import 'package:bett_box/models/media_unlock.dart';

/// 探测方式决定 `MediaUnlockChecker` 走哪套解析逻辑；新增一种就在这里加子类，
/// 并在 `MediaUnlockChecker._checkServiceType` 补一条分支。
sealed class ServiceProbe {
  const ServiceProbe();
}

/// Cloudflare `/cdn-cgi/trace` 文本探测：解出 ip/loc/colo/warp，拿不到 ip 视为被挡。
final class TraceProbe extends ServiceProbe {
  const TraceProbe({
    required this.hosts,
    this.blockedRegions = const {},
    this.fallbackUrl,
  });

  /// 依次尝试，拿到 ip 就停。
  final List<String> hosts;

  /// 出口地区命中即判不可用；留空表示只看边缘能否应答。
  final Set<String> blockedRegions;

  /// trace 拿不到结果时的页面兜底，只能判断通不通，没有地区。
  final String? fallbackUrl;
}

/// 服务页面 HTML 里用正则抽地区，给不暴露 trace 的服务用。
final class HtmlRegionProbe extends ServiceProbe {
  const HtmlRegionProbe({this.blockedRegions = const {}});

  final Set<String> blockedRegions;
}

/// 一个分流类型：同时描述分流规则集和该服务的连通性判定。
///
/// [platform] 复用媒体解锁的结果模型，所以类型既是分流项也是检测项；
/// [key] 与 `assets/scripts/routing.json` 的 rule-set tag 对齐。
class ServiceType {
  const ServiceType({
    required this.key,
    required this.name,
    required this.icon,
    required this.platform,
    required this.category,
    required this.sets,
    required this.probe,
  });

  final String key;
  final String name;
  final String icon;
  final MediaPlatform platform;
  final RouteCategory category;

  /// 分流页可选的规则集，`geosite:`/`geoip:` 前缀与 routing.json 的 set 一一对应。
  final List<String> sets;
  final ServiceProbe probe;
}

/// OpenAI 按账号条款不可用的地区；港澳节点即使网络通畅也判 blocked。
const openaiBlockedRegions = {
  'CN',
  'HK',
  'MO',
  'RU',
  'IR',
  'KP',
  'SY',
  'CU',
  'VE',
  'BY',
  'AF',
  'SS',
  'YE',
  'ZW',
  'MM',
  'SD',
  'SO',
  'CF',
};

const geminiBlockedRegions = {
  'CHN',
  'CN',
  'RUS',
  'RU',
  'BLR',
  'BY',
  'IRN',
  'IR',
  'PRK',
  'KP',
  'SYR',
  'SY',
  'CUB',
  'CU',
  'VEN',
  'VE',
  'MMR',
  'MM',
  'SDN',
  'SD',
  'AFG',
  'AF',
  'SSD',
  'SS',
  'YEM',
  'YE',
  'ZWE',
  'ZW',
};

/// 目前已收进注册表的分流类型。其他平台仍走 `MediaUnlockChecker` 里的老分支。
const serviceTypes = <ServiceType>[
  ServiceType(
    key: 'openai',
    name: 'ChatGPT',
    icon: 'ChatGPT.svg',
    platform: MediaPlatform.openai,
    category: RouteCategory.ai,
    sets: ['geosite:openai', 'geoip:openai'],
    probe: TraceProbe(
      hosts: ['chatgpt.com'],
      blockedRegions: openaiBlockedRegions,
    ),
  ),
  ServiceType(
    key: 'google-gemini',
    name: 'Gemini',
    icon: 'Gemini.svg',
    platform: MediaPlatform.gemini,
    category: RouteCategory.ai,
    sets: ['geosite:google-gemini'],
    probe: HtmlRegionProbe(blockedRegions: geminiBlockedRegions),
  ),
];

final Map<String, ServiceType> serviceTypeByKey = Map.unmodifiable({
  for (final type in serviceTypes) type.key: type,
});

final Map<MediaPlatform, ServiceType> serviceTypeByPlatform = Map.unmodifiable({
  for (final type in serviceTypes) type.platform: type,
});
