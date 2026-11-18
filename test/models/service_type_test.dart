import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:bett_box/enum/enum.dart';
import 'package:bett_box/models/models.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('ServiceType registry', () {
    test('key 与 platform 不重复', () {
      final keys = serviceTypes.map((type) => type.key).toList();
      final platforms = serviceTypes.map((type) => type.platform).toList();
      expect(keys.toSet().length, keys.length);
      expect(platforms.toSet().length, platforms.length);
      expect(serviceTypeByKey.keys.toSet(), keys.toSet());
      expect(serviceTypeByPlatform.keys.toSet(), platforms.toSet());
    });

    test('每个类型都有名称、图标、规则集与探测', () {
      for (final type in serviceTypes) {
        expect(type.name, isNotEmpty, reason: type.key);
        expect(type.icon, isNotEmpty, reason: type.key);
        expect(type.sets, isNotEmpty, reason: type.key);
        expect(type.category, isNotNull, reason: type.key);
        for (final set in type.sets) {
          expect(
            set,
            matches(RegExp(r'^geosite:.+|^geoip:.+')),
            reason: '${type.key} 的规则集必须以 geosite:/geoip: 开头',
          );
        }
        switch (type.probe) {
          case TraceProbe probe:
            expect(probe.hosts, isNotEmpty, reason: type.key);
            for (final host in probe.hosts) {
              expect(host, isNot(contains('/')), reason: '${type.key} 只写域名');
            }
          case HtmlRegionProbe probe:
            expect(probe.url, isNotEmpty, reason: type.key);
            expect(probe.regionPatterns, isNotEmpty, reason: type.key);
        }
      }
    });

    test('OpenAI 用 trace 探测且地区黑名单含港澳', () {
      final type = serviceTypeByKey['openai']!;
      expect(type.platform, MediaPlatform.openai);
      expect(type.category, RouteCategory.ai);
      expect(type.sets, containsAll(['geosite:openai', 'geoip:openai']));

      final probe = type.probe as TraceProbe;
      expect(probe.hosts.first, 'chatgpt.com');
      expect(probe.blockedRegions, containsAll(['CN', 'HK', 'MO']));
      expect(probe.blockedRegions, isNot(contains('US')));
      expect(probe.blockedRegions, isNot(contains('JP')));
    });

    test('Gemini 用页面地区探测且地区黑名单含 CN/RU', () {
      final type = serviceTypeByKey['google-gemini']!;
      expect(type.platform, MediaPlatform.gemini);
      expect(type.sets, contains('geosite:google-gemini'));

      final probe = type.probe as HtmlRegionProbe;
      expect(probe.blockedRegions, containsAll(['CHN', 'CN', 'RUS', 'RU']));
      expect(probe.blockedRegions, isNot(contains('USA')));
    });

    test('YouTube 只按请求能否成功探测，不按地区降级', () {
      final type = serviceTypeByKey['youtube']!;
      expect(type.platform, MediaPlatform.youtube);
      expect(type.category, RouteCategory.streaming);
      expect(type.sets, contains('geosite:youtube'));

      final probe = type.probe as HtmlRegionProbe;
      expect(probe.url, 'https://www.youtube.com/premium');
      expect(probe.blockedRegions, isEmpty);
      expect(
        probe.blockedPaths,
        containsAll(['sorry.google.com', 'www.google.cn']),
      );
      expect(probe.unavailablePhrases, isNotEmpty);
      expect(
        probe.limitedPhrases,
        contains('premium is not available in your country'),
      );
    });

    test('地区黑名单与内核 service_probe.go 一致', () {
      final source = File(
        'core/Clash.Meta/adapter/outboundgroup/service_probe.go',
      ).readAsStringSync();

      Set<String> goRegions(String key) {
        final presetStart = source.indexOf('"$key": {');
        expect(presetStart, greaterThan(-1), reason: 'Go 侧缺少 $key preset');
        final callStart = source.indexOf('serviceRegionSet(', presetStart);
        final callEnd = source.indexOf(')', callStart);
        expect(callEnd, greaterThan(callStart));
        return RegExp(r'"([A-Z]{2,3})"')
            .allMatches(source.substring(callStart, callEnd))
            .map((match) => match.group(1)!)
            .toSet();
      }

      expect(goRegions('openai'), openaiBlockedRegions);
      expect(goRegions('google-gemini'), geminiBlockedRegions);
      expect(goRegions('youtube'), youtubeBlockedRegions);
    });

    test('规则集在 routing.json 里都存在', () {
      final raw = File(
        'assets/scripts/routing.json',
      ).readAsStringSync();
      final catalog = jsonDecode(raw) as Map<String, dynamic>;
      final tags = <String>{
        for (final set in catalog['sets'] as List)
          '${(set as Map)['type'] ?? 'geosite'}:${set['tag']}',
      };

      for (final type in serviceTypes) {
        for (final set in type.sets) {
          expect(
            tags,
            contains(set),
            reason: '${type.key} 的 $set 在 routing.json 中找不到',
          );
        }
      }
    });
  });
}
