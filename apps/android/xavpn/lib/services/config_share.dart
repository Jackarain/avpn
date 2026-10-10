import 'dart:convert';
import 'dart:io' show ZLibCodec, ZLibOption;

import '../models/vpn_config.dart';

/// 二维码分享内容的类型标识与版本, 用于识别是否为本应用的配置码.
const String _shareType = 'xavpn-config';
const int _shareVersion = 1;

/// 压缩格式前缀: deflate + base64url.
const String _sharePrefix = 'xavpn1:';

/// 最高级别 deflate: dart:io 内置 zlib 提供, 无需额外依赖.
final ZLibCodec _deflate = ZLibCodec(level: ZLibOption.maxLevel);

/// 生成配置二维码的内容.
///
/// json 正文经 deflate 压缩后再做 base64url, 缩小二维码数据量.
String encodeConfigShare(VpnConfig config) {
  final json = jsonEncode({
    'type': _shareType,
    'version': _shareVersion,
    'config': config.toJson(),
  });
  return '$_sharePrefix${base64Url.encode(_deflate.encode(utf8.encode(json)))}';
}

/// 解析扫码得到的配置内容; 内容非法时抛出 [FormatException].
///
/// 返回的配置沿用二维码里的 id, 是否重新生成 id 由调用方决定.
VpnConfig decodeConfigShare(String raw) {
  final decoded = _decodePayload(raw);
  if (decoded is! Map<String, dynamic> || decoded['type'] != _shareType) {
    throw const FormatException('二维码不是 aVPN 配置');
  }
  final config = decoded['config'];
  if (config is! Map<String, dynamic>) {
    throw const FormatException('二维码缺少配置内容');
  }
  return VpnConfig.fromJson(config);
}

/// 解出正文 JSON: 支持前缀压缩, 兼容未压缩的明文 JSON.
Object? _decodePayload(String raw) {
  final text = raw.trim();
  if (text.startsWith(_sharePrefix)) {
    try {
      final packed = base64Url.decode(text.substring(_sharePrefix.length));
      return jsonDecode(utf8.decode(_deflate.decode(packed)));
    } on FormatException {
      throw const FormatException('二维码内容无法解析');
    }
  }
  if (text.startsWith('{')) return jsonDecode(text);
  throw const FormatException('二维码不是 aVPN 配置');
}
