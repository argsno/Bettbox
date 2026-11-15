import 'dart:convert';
import 'dart:io';

import 'package:bett_box/common/common.dart';
import 'package:code_forge/script.dart';
import 'package:flutter_test/flutter_test.dart';

import '../plugins/code_forge/support.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late Directory directory;
  setUpAll(() async {
    await initEditorNative();
    directory = await Directory.systemTemp.createTemp('managed_smart_test');
  });
  tearDownAll(() async {
    await directory.delete(recursive: true);
  });

  Future<Map<String, dynamic>> generate(
    Map<String, bool> options, {
    String prelude = '',
  }) async {
    final input = File('${directory.path}/input.json');
    final output = File('${directory.path}/output.json');
    input.writeAsStringSync(
      json.encode({
        'proxies': [
          {
            'name': 'HK 01',
            'type': 'ss',
            'server': 'hk.example.com',
            'port': 443,
            'cipher': 'aes-128-gcm',
            'password': 'pw',
          },
          {
            'name': 'HK 02',
            'type': 'ss',
            'server': 'hk2.example.com',
            'port': 443,
            'cipher': 'aes-128-gcm',
            'password': 'pw',
          },
        ],
        'proxy-groups': <Object>[],
        'rules': <Object>[],
      }),
    );
    await evaluateScriptFile(
      script: [
        if (prelude.isNotEmpty) prelude,
        await ManagedScript.readBundled(),
      ].join('\n'),
      inputPath: input.path,
      outputPath: output.path,
      customOptions: json.encode(options),
      token: 1,
    );
    return json.decode(output.readAsStringSync()) as Map<String, dynamic>;
  }

  List<Map> groups(Map<String, dynamic> config) =>
      (config['proxy-groups'] as List).cast<Map>();

  List<String> groupTypes(Map<String, dynamic> config) => [
    for (final group in groups(config)) '${group['name']}:${group['type']}',
  ];

  Map group(Map<String, dynamic> config, String name) =>
      groups(config).firstWhere((group) => group['name'] == name);

  test('smart select is off by default', () async {
    final config = await generate({'自动选择': true, '生成地区自动选择组': true});
    final types = groupTypes(config);
    expect(types, contains('自动选择:url-test'));
    expect(types, contains('香港-自动选择:url-test'));
    expect(types.where((type) => type.endsWith(':smart')), isEmpty);
  });

  test('smart select adds a smart group next to the auto groups', () async {
    final config = await generate({
      '自动选择': true,
      '生成地区自动选择组': true,
      '智能选择': true,
    });
    final types = groupTypes(config);
    expect(types, contains('自动选择:url-test'));
    expect(types, contains('智能选择:smart'));
    expect(types, contains('香港-自动选择:url-test'));
    expect(types.where((type) => type.endsWith(':url-test')).length, 2);

    final smart = group(config, '智能选择');
    expect(smart['proxies'], ['🇭🇰 HK 01', '🇭🇰 HK 02']);
    expect(smart['interval'], isNull);
    expect(smart['lazy'], isNull);
    expect(smart['tolerance'], isNull);
    expect(smart['exclude-type'], 'DIRECT');
    expect(group(config, '默认代理')['proxies'], ['香港', '手动选择', '自动选择', '智能选择']);
    expect(group(config, 'AI')['proxies'], contains('智能选择'));
  });

  test('region smart groups follow their own switch', () async {
    final autoOnly = await generate({'生成地区自动选择组': true});
    expect(groupTypes(autoOnly), contains('香港-自动选择:url-test'));
    expect(groupTypes(autoOnly), isNot(contains('香港-智能选择:smart')));

    final smartOnly = await generate({'生成地区智能选择组': true});
    expect(groupTypes(smartOnly), contains('香港-智能选择:smart'));
    expect(groupTypes(smartOnly), isNot(contains('香港-自动选择:url-test')));
    expect(group(smartOnly, '香港')['proxies'], [
      '香港-智能选择',
      '🇭🇰 HK 01',
      '🇭🇰 HK 02',
    ]);

    final both = await generate({'生成地区自动选择组': true, '生成地区智能选择组': true});
    final types = groupTypes(both);
    expect(types, contains('香港-自动选择:url-test'));
    expect(types, contains('香港-智能选择:smart'));
    expect(group(both, '香港')['proxies'], [
      '香港-自动选择',
      '香港-智能选择',
      '🇭🇰 HK 01',
      '🇭🇰 HK 02',
    ]);

    final globalOnly = await generate({'智能选择': true});
    expect(groupTypes(globalOnly), contains('智能选择:smart'));
    expect(groupTypes(globalOnly), isNot(contains('香港-智能选择:smart')));
  });

  test('region smart group follows the saved region order', () async {
    final config = await generate({
      '生成地区自动选择组': true,
      '生成地区智能选择组': true,
    }, prelude: "const bettboxOrder = ['香港'];");
    final types = groupTypes(config);
    expect(
      types.indexOf('香港-自动选择:url-test'),
      lessThan(types.indexOf('香港-智能选择:smart')),
    );
    expect(
      types.indexOf('香港-智能选择:smart'),
      lessThan(types.indexOf('香港:select')),
    );
  });

  test('minimal mode adds smart select too', () async {
    final config = await generate({
      '自动选择': true,
      '极简国内外分流模式': true,
      '智能选择': true,
    });
    expect(groupTypes(config), [
      '默认代理:select',
      '自动选择:url-test',
      '智能选择:smart',
      'AdBlock:select',
      '直连:select',
    ]);
    expect(group(config, '默认代理')['proxies'], [
      '🇭🇰 HK 01',
      '🇭🇰 HK 02',
      '自动选择',
      '智能选择',
    ]);
  });

  test('smart select works without the url-test auto group', () async {
    final config = await generate({'极简国内外分流模式': true, '智能选择': true});
    expect(groupTypes(config), [
      '默认代理:select',
      '智能选择:smart',
      'AdBlock:select',
      '直连:select',
    ]);
  });

  test('subscription groups are off by default', () async {
    final config = await generate({
      '自动选择': true,
      '智能选择': true,
    }, prelude: "const bettboxSubscriptionPrefix = 'A';");
    expect(groupTypes(config).where((type) => type.startsWith('订阅 ')), isEmpty);
  });

  test('subscription groups follow the prefix and switches', () async {
    final config = await generate({
      '每订阅一个分组': true,
      '自动选择': true,
      '智能选择': true,
    }, prelude: "const bettboxSubscriptionPrefix = 'A';");
    final types = groupTypes(config);
    expect(types, contains('订阅 A:select'));
    expect(types, contains('订阅 A-自动选择:url-test'));
    expect(types, contains('订阅 A-智能选择:smart'));
    expect(group(config, '订阅 A')['proxies'], [
      '订阅 A-自动选择',
      '订阅 A-智能选择',
      '🇭🇰 HK 01',
      '🇭🇰 HK 02',
    ]);
    expect(group(config, '默认代理')['proxies'], contains('订阅 A'));
    expect(group(config, 'AI')['proxies'], contains('订阅 A'));
  });

  test('subscription groups only add enabled sub groups', () async {
    final config = await generate({
      '每订阅一个分组': true,
      '智能选择': true,
    }, prelude: "const bettboxSubscriptionPrefix = 'B';");
    expect(groupTypes(config), contains('订阅 B:select'));
    expect(groupTypes(config), contains('订阅 B-智能选择:smart'));
    expect(groupTypes(config), isNot(contains('订阅 B-自动选择:url-test')));
    expect(group(config, '订阅 B')['proxies'], [
      '订阅 B-智能选择',
      '🇭🇰 HK 01',
      '🇭🇰 HK 02',
    ]);
  });

  test('subscription groups need a bundle prefix', () async {
    final config = await generate({'每订阅一个分组': true, '自动选择': true});
    expect(groupTypes(config).where((type) => type.startsWith('订阅 ')), isEmpty);
  });

  test('subscription groups work in minimal mode', () async {
    final config = await generate({
      '每订阅一个分组': true,
      '极简国内外分流模式': true,
      '智能选择': true,
    }, prelude: "const bettboxSubscriptionPrefix = 'C';");
    final types = groupTypes(config);
    expect(types, contains('订阅 C:select'));
    expect(types, contains('订阅 C-智能选择:smart'));
    expect(group(config, '默认代理')['proxies'], contains('订阅 C'));
  });
}
