import 'package:bett_box/enum/enum.dart';
import 'package:bett_box/models/models.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('GroupType.Smart', () {
    test('解析 profile 中的 smart 类型', () {
      expect(GroupType.parseProfileType('smart'), GroupType.Smart);
    });

    test('当前节点由核心计算', () {
      expect(GroupType.Smart.isComputedSelected, isTrue);
    });

    test('解码核心返回的 Smart 组数据', () {
      final group = Group.fromJson(const {
        'name': 'smart-auto',
        'type': 'Smart',
        'all': <Object>[],
        'now': 'A',
      });

      expect(group.type, GroupType.Smart);
      expect(group.now, 'A');
    });

    test('序列化 Smart 组类型', () {
      const group = Group(name: 'smart-auto', type: GroupType.Smart);

      expect(group.toJson()['type'], 'Smart');
    });

    test('ProxyGroup 模型可以解析 smart 组配置', () {
      final group = ProxyGroup.fromJson(const {
        'name': 'smart-auto',
        'type': 'smart',
      });

      expect(group.type, GroupType.Smart);
    });
  });
}
