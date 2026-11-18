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
  const HtmlRegionProbe({
    required this.url,
    required this.regionPatterns,
    this.blockedRegions = const {},
    this.blockedPaths = const [],
    this.unavailablePhrases = const [],
    this.limitedPhrases = const [],
    this.maxBody = 256 * 1024,
  });

  final String url;

  /// 按顺序尝试，第一处命中即为地区；写成字符串以保持注册表 const。
  final List<String> regionPatterns;

  /// 出口地区命中即判不可用。
  final Set<String> blockedRegions;

  /// 最终地址包含这些片段即判不可用，例如 sorry.google.com。
  final List<String> blockedPaths;

  /// 页面含这些短语（小写匹配）即判不可用。
  final List<String> unavailablePhrases;

  /// 页面含这些短语时只判受限，不影响视频播放，例如缺少 Premium。
  final List<String> limitedPhrases;

  /// 最多读取的响应体字节数；0 表示读到流结束。Gemini 的地区字段在页面后段。
  final int maxBody;
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

/// YouTube 没有地区黑名单：不可用只由请求本身（跳转、状态码、页面文案）判定。
const youtubeBlockedRegions = <String>{};

const geminiRegionPatterns = [
  r',2,1,200,"([A-Z]{3})"',
  r'\[1,null,null,\d+,\d+,"([A-Z]{3})"',
];

const geminiUnavailablePhrases = [
  'not supported in your country',
  "isn't supported in your country",
  'not available in your country',
  'unavailable in your country',
  'not currently supported',
  "isn't currently supported",
  '不支持您所在的国家',
  '不支持你所在的国家',
  '无法在您所在的国家',
  '無法在您所在的國家',
  'ご利用いただけません',
];

/// YouTube 只按请求能否成功排序：服务端不按出口地区拒绝请求，所以没有地区黑名单。
/// Premium 不可用只影响面板标记，不影响视频播放，不能用来降级节点。
const youtubeRegionPatterns = [
  r'"INNERTUBE_CONTEXT_GL"\s*:\s*"([A-Z]{2})"',
  r'"countryCode"\s*:\s*"([A-Z]{2})"',
  r'"REQUEST_DOMAIN"\s*:\s*"([a-zA-Z]{2})"',
];

const youtubeUnavailablePhrases = [
  "youtube isn't available in your country",
  'youtube is not available in your country',
  'youtube is unavailable in your country',
  'www.google.cn',
];

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
    probe: HtmlRegionProbe(
      url: 'https://gemini.google.com/',
      regionPatterns: geminiRegionPatterns,
      blockedRegions: geminiBlockedRegions,
      blockedPaths: ['sorry.google.com', 'unavailable'],
      unavailablePhrases: geminiUnavailablePhrases,
      maxBody: 0,
    ),
  ),
  ServiceType(
    key: 'youtube',
    name: 'YouTube',
    icon: 'YouTube.svg',
    platform: MediaPlatform.youtube,
    category: RouteCategory.streaming,
    sets: ['geosite:youtube'],
    probe: HtmlRegionProbe(
      url: 'https://www.youtube.com/premium',
      regionPatterns: youtubeRegionPatterns,
      blockedRegions: youtubeBlockedRegions,
      blockedPaths: ['sorry.google.com', 'www.google.cn'],
      unavailablePhrases: youtubeUnavailablePhrases,
      limitedPhrases: [
        'premium is not available in your country',
        'unavailable in your country',
      ],
    ),
  ),
];

final Map<String, ServiceType> serviceTypeByKey = Map.unmodifiable({
  for (final type in serviceTypes) type.key: type,
});

final Map<MediaPlatform, ServiceType> serviceTypeByPlatform = Map.unmodifiable({
  for (final type in serviceTypes) type.platform: type,
});
