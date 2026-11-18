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

  test('built-in YouTube group gets a service smart subgroup', () async {
    final config = await generate({'智能选择': true});

    expect(groupTypes(config), contains('YouTube-智能选择:smart'));
    final types = groupTypes(config);
    expect(
      types.indexOf('YouTube-智能选择:smart'),
      lessThan(types.indexOf('YouTube:select')),
    );
    final smart = group(config, 'YouTube-智能选择');
    expect(smart['service'], 'youtube');
    expect(smart['proxies'], ['🇭🇰 HK 01', '🇭🇰 HK 02']);
    final youtube = group(config, 'YouTube');
    expect(youtube['proxies'], [
      'YouTube-智能选择',
      '默认代理',
      '手动选择',
      '智能选择',
      '香港',
    ]);
    expect(youtube['default-selected'], 'YouTube-智能选择');
  });

  test('built-in YouTube group stays unchanged without smart select', () async {
    final config = await generate({'自动选择': true});

    expect(groupTypes(config), contains('YouTube:select'));
    expect(groupTypes(config), isNot(contains('YouTube-智能选择:smart')));
    expect(group(config, 'YouTube')['proxies'], [
      '默认代理',
      '手动选择',
      '自动选择',
      '香港',
    ]);
    expect(group(config, 'YouTube').containsKey('service'), false);
    expect(group(config, 'YouTube').containsKey('default-selected'), false);
  });

  test('built-in YouTube subgroup follows the YouTube switch', () async {
    final config = await generate({'智能选择': true, 'YouTube': false});

    expect(groupTypes(config), isNot(contains('YouTube:select')));
    expect(groupTypes(config), isNot(contains('YouTube-智能选择:smart')));
  });

  test('built-in YouTube subgroup sorts before its parent', () async {
    final config = await generate(
      {'智能选择': true},
      prelude: "const bettboxOrder = ['YouTube','YouTube-智能选择'];",
    );

    final types = groupTypes(config);
    expect(
      types.indexOf('YouTube-智能选择:smart'),
      lessThan(types.indexOf('YouTube:select')),
      reason: 'proxy group order: $types',
    );
  });

  test('built-in YouTube subgroup yields to a same-named route', () async {
    const clashRoute =
        "{'name':'YouTube-智能选择','sets':[{'type':'geosite','tag':'youtube'}],'target':'直连'}";
    final config = await generate(
      {'智能选择': true},
      prelude: 'const bettboxRoutes = [$clashRoute];',
    );

    final names = [for (final group in groups(config)) group['name'] as String];
    expect(
      names.toSet().length,
      names.length,
      reason: 'duplicate proxy group names: $names',
    );
    expect(
      group(config, 'YouTube')['proxies'],
      isNot(contains('YouTube-智能选择')),
    );
  });

  const chatGPTRoute =
      "{'name':'ChatGPT','sets':[{'type':'geosite','tag':'openai'}],'target':'直连'}";
  const chatGPTRoutePrelude = 'const bettboxRoutes = [$chatGPTRoute];';

  test('custom YouTube route gets a service smart subgroup', () async {
    const youtubeRoute =
        "{'name':'YouTube 自定义','sets':[{'type':'geosite','tag':'youtube'}],'target':'直连'}";
    final config = await generate(
      {'智能选择': true},
      prelude: 'const bettboxRoutes = [$youtubeRoute];',
    );

    expect(groupTypes(config), contains('YouTube 自定义-智能选择:smart'));
    expect(group(config, 'YouTube 自定义-智能选择')['service'], 'youtube');
  });

  test('custom service route gets a smart subgroup', () async {
    final config = await generate({'智能选择': true}, prelude: chatGPTRoutePrelude);

    expect(groupTypes(config), contains('ChatGPT-智能选择:smart'));
    final types = groupTypes(config);
    expect(
      types.indexOf('ChatGPT-智能选择:smart'),
      lessThan(types.indexOf('ChatGPT:select')),
    );
    final smart = group(config, 'ChatGPT-智能选择');
    expect(smart['service'], 'openai');
    expect(smart['proxies'], ['🇭🇰 HK 01', '🇭🇰 HK 02']);
    expect(group(config, 'ChatGPT')['proxies'], [
      'ChatGPT-智能选择',
      '默认代理',
      '手动选择',
      '智能选择',
      '香港',
      '直连',
    ]);
  });

  test('custom service route keeps its explicit default target', () async {
    final config = await generate({'智能选择': true}, prelude: chatGPTRoutePrelude);

    expect(group(config, 'ChatGPT')['default-selected'], '直连');
  });

  test('custom service route stays unchanged without smart select', () async {
    final config = await generate({'自动选择': true}, prelude: chatGPTRoutePrelude);

    expect(groupTypes(config), isNot(contains('ChatGPT-智能选择:smart')));
    expect(
      groups(config).where((group) => group['name'] == 'ChatGPT-智能选择'),
      isEmpty,
    );
    expect(
      groups(config).where(
        (group) => group['type'] == 'smart' && group['name'] == 'ChatGPT-智能选择',
      ),
      isEmpty,
    );
  });

  test('custom service route dedupes its derived smart name', () async {
    const clashRoute =
        "{'name':'ChatGPT-智能选择','sets':[{'type':'geosite','tag':'openai'}],'target':'直连'}";
    Future<Map<String, dynamic>> withRoutes(String routes) =>
        generate({'智能选择': true}, prelude: 'const bettboxRoutes = $routes;');

    Set<String> serviceSmartGroups(Map<String, dynamic> config) => {
      for (final group in groups(config))
        if (group['type'] == 'smart' && group['service'] == 'openai')
          group['name'] as String,
    };

    // The colliding route is declared first, so it owns `ChatGPT-智能选择` and the
    // guard drops ChatGPT's derived name: one smart group, from the colliding
    // route, and ChatGPT keeps its plain member list.
    const clashFirst = '[$clashRoute,$chatGPTRoute]';
    final clashFirstConfig = await withRoutes(clashFirst);
    final clashFirstNames = [
      for (final group in groups(clashFirstConfig)) group['name'] as String,
    ];
    expect(
      clashFirstNames.toSet().length,
      clashFirstNames.length,
      reason: 'duplicate proxy group names in $clashFirst: $clashFirstNames',
    );
    final clashFirstChatGPT = group(clashFirstConfig, 'ChatGPT');
    expect(clashFirstChatGPT['proxies'], isNot(contains('ChatGPT-智能选择')));
    expect(clashFirstChatGPT['default-selected'], '直连');
    // A removed guard would add a second smart group here.
    expect(serviceSmartGroups(clashFirstConfig), {'ChatGPT-智能选择-智能选择'});

    // ChatGPT comes first and claims the derived name, so the duplicate-named
    // route is dropped instead and ChatGPT keeps exactly that one subgroup.
    const chatGPTFirst = '[$chatGPTRoute,$clashRoute]';
    final chatGPTFirstConfig = await withRoutes(chatGPTFirst);
    final chatGPTFirstNames = [
      for (final group in groups(chatGPTFirstConfig)) group['name'] as String,
    ];
    expect(
      chatGPTFirstNames.toSet().length,
      chatGPTFirstNames.length,
      reason:
          'duplicate proxy group names in $chatGPTFirst: $chatGPTFirstNames',
    );
    final chatGPTFirstChatGPT = group(chatGPTFirstConfig, 'ChatGPT');
    expect((chatGPTFirstChatGPT['proxies'] as List).first, 'ChatGPT-智能选择');
    expect(chatGPTFirstChatGPT['default-selected'], '直连');
    expect(serviceSmartGroups(chatGPTFirstConfig), {'ChatGPT-智能选择'});
  });

  test('derived smart subgroup sorts before its parent', () async {
    const clashRoute =
        "{'name':'ChatGPT-智能选择','sets':[{'type':'geosite','tag':'openai'}],'target':'直连'}";
    // The saved order names the derived group after its parent; the core parses
    // groups in order, so a subgroup emitted later than its parent fails to load.
    final config = await generate(
      {'智能选择': true},
      prelude:
          'const bettboxRoutes = [$chatGPTRoute,$clashRoute];\n'
          "const bettboxOrder = ['ChatGPT','ChatGPT-智能选择'];",
    );

    final types = groupTypes(config);
    expect(
      types.indexOf('ChatGPT-智能选择:smart'),
      lessThan(types.indexOf('ChatGPT:select')),
      reason: 'proxy group order: $types',
    );
  });
}
