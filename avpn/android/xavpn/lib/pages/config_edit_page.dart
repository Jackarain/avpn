import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../models/vpn_config.dart';

class ConfigEditPage extends StatefulWidget {
  const ConfigEditPage({super.key, required this.config, required this.isNew});

  final VpnConfig config;
  final bool isNew;

  @override
  State<ConfigEditPage> createState() => _ConfigEditPageState();
}

class _ConfigEditPageState extends State<ConfigEditPage> {
  late final VpnConfig c = widget.config;
  late final TextEditingController _name = TextEditingController(text: c.name);
  late final TextEditingController _nexthop = TextEditingController(
    text: c.nexthop,
  );
  late final TextEditingController _privateKey = TextEditingController(
    text: c.privateKey,
  );
  late final TextEditingController _publicKey = TextEditingController(
    text: c.publicKey,
  );
  late final TextEditingController _pkl = TextEditingController(
    text: c.pkl.join('\n'),
  );
  late final TextEditingController _mtu = TextEditingController(
    text: c.mtuSize.toString(),
  );
  late final TextEditingController _keepalive = TextEditingController(
    text: c.keepalive.toString(),
  );
  late final TextEditingController _dataShards = TextEditingController(
    text: c.dataShards.toString(),
  );
  late final TextEditingController _parityShards = TextEditingController(
    text: c.parityShards.toString(),
  );
  late final TextEditingController _obfuscate = TextEditingController(
    text: c.obfuscateKey,
  );
  late final TextEditingController _udpListen = TextEditingController(
    text: c.udpListen.join('\n'),
  );
  late final TextEditingController _tcpListen = TextEditingController(
    text: c.tcpListen.join('\n'),
  );
  late final TextEditingController _subnet = TextEditingController(
    text: c.subnet,
  );
  late final TextEditingController _pushroutes = TextEditingController(
    text: c.pushroutes.join('\n'),
  );
  late final TextEditingController _pushdns = TextEditingController(
    text: c.pushdns.toString(),
  );
  late final TextEditingController _bypassroutes = TextEditingController(
    text: c.bypassroutes.join('\n'),
  );
  late final TextEditingController _routes = TextEditingController(
    text: c.routes.join('\n'),
  );
  late final TextEditingController _dns = TextEditingController(
    text: c.dns.join('\n'),
  );
  late final TextEditingController _testUrl = TextEditingController(
    text: c.testUrl,
  );

  @override
  void dispose() {
    for (final t in [
      _name,
      _nexthop,
      _privateKey,
      _publicKey,
      _pkl,
      _mtu,
      _keepalive,
      _dataShards,
      _parityShards,
      _obfuscate,
      _udpListen,
      _tcpListen,
      _subnet,
      _pushroutes,
      _pushdns,
      _bypassroutes,
      _routes,
      _dns,
      _testUrl,
    ]) {
      t.dispose();
    }
    super.dispose();
  }

  int _toInt(String v, int def) => int.tryParse(v.trim()) ?? def;

  List<String> _lines(String v) =>
      v
          .split(RegExp(r'[\r\n,;]+'))
          .map((s) => s.trim())
          .where((s) => s.isNotEmpty)
          .toList();

  void _save() {
    final vpn =
        c
          ..name = _name.text.trim().isEmpty ? '未命名' : _name.text.trim()
          ..mode = _mode
          ..nexthop = _nexthop.text.trim()
          ..privateKey = _privateKey.text.trim()
          ..publicKey = _publicKey.text.trim()
          ..pkl = _lines(_pkl.text)
          ..mtuSize = _toInt(_mtu.text, 1450)
          ..keepalive = _toInt(_keepalive.text, 60)
          ..dataShards = _toInt(_dataShards.text, 0)
          ..parityShards = _toInt(_parityShards.text, 0)
          ..compress = _compress
          ..obfuscateKey = _obfuscate.text.trim()
          ..udpListen = _lines(_udpListen.text)
          ..tcpListen = _lines(_tcpListen.text)
          ..subnet = _subnet.text.trim()
          ..passbyvpn = _passbyvpn
          ..pushroutes = _lines(_pushroutes.text)
          ..pushdns = _toInt(_pushdns.text, 0)
          ..ignorePush = _ignorePush
          ..c2c = _c2c
          ..bypassroutes = _lines(_bypassroutes.text)
          ..routes = _lines(_routes.text)
          ..dns = _lines(_dns.text)
          ..testUrl = _testUrl.text.trim();
    // TUN 地址/前缀由 subnet 自动推导 (客户端=网络地址+2, 网关=网络地址+1),
    // 保证与服务端 subnet 一致, 避免手工填错导致无法上网.
    final derivedTun = vpn.deriveTun();
    vpn.tunAddress = derivedTun.$1;
    vpn.tunPrefix = derivedTun.$2;
    final errors = vpn.validate();
    if (errors.isNotEmpty) {
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text(errors.join('\n'))));
      return;
    }
    Navigator.of(context).pop(vpn);
  }

  late String _mode = c.mode;
  late String _compress = c.compress;
  late bool _passbyvpn = c.passbyvpn;
  late bool _ignorePush = c.ignorePush;
  late bool _c2c = c.c2c;

  /// 依据当前表单 subnet 预览自动推导的 TUN 地址/前缀.
  (String, int) _tunPreview() {
    final tmp = VpnConfig(id: '', name: '', mode: _mode)
      ..subnet = _subnet.text.trim()
      ..tunAddress = c.tunAddress
      ..tunPrefix = c.tunPrefix;
    return tmp.deriveTun();
  }

  @override
  Widget build(BuildContext context) {
    final isGateway = _mode == 'gateway';
    return Scaffold(
      appBar: AppBar(
        title: Text(widget.isNew ? '添加配置' : '编辑配置'),
        actions: [TextButton(onPressed: _save, child: const Text('保存'))],
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          _section('基本'),
          TextField(
            controller: _name,
            decoration: const InputDecoration(
              labelText: '名称',
              border: OutlineInputBorder(borderRadius: BorderRadius.zero),
            ),
          ),
          const SizedBox(height: 12),
          DropdownButtonFormField<String>(
            value: _mode,
            decoration: const InputDecoration(
              labelText: '模式',
              border: OutlineInputBorder(borderRadius: BorderRadius.zero),
            ),
            items: const [
              DropdownMenuItem(value: 'client', child: Text('客户端 (Client)')),
              DropdownMenuItem(value: 'gateway', child: Text('网关 (Gateway)')),
            ],
            onChanged: (v) => setState(() => _mode = v ?? 'client'),
          ),
          const SizedBox(height: 12),
          if (!isGateway) ...[
            TextField(
              controller: _nexthop,
              decoration: const InputDecoration(
                labelText: 'Nexthop 服务器',
                hintText: '例如 1.2.3.4:19090 或 tcp://1.2.3.4:19090',
                border: OutlineInputBorder(borderRadius: BorderRadius.zero),
              ),
            ),
            const SizedBox(height: 12),
          ],

          _section('密钥'),
          TextField(
            controller: _privateKey,
            decoration: const InputDecoration(
              labelText: '本端私钥 private_key',
              border: OutlineInputBorder(borderRadius: BorderRadius.zero),
            ),
          ),
          const SizedBox(height: 12),
          TextField(
            controller: _publicKey,
            decoration: const InputDecoration(
              labelText: '对端公钥 public_key',
              hintText: '服务器/网关的公钥 (base64), 客户端必填',
              border: OutlineInputBorder(borderRadius: BorderRadius.zero),
            ),
          ),
          const SizedBox(height: 12),
          TextField(
            controller: _pkl,
            maxLines: 3,
            decoration: const InputDecoration(
              labelText: '对端公钥列表 pkl (每行一个)',
              border: OutlineInputBorder(borderRadius: BorderRadius.zero),
            ),
          ),
          const SizedBox(height: 12),

          _section('传输参数'),
          Row(
            children: [
              Expanded(
                child: TextField(
                  controller: _mtu,
                  keyboardType: TextInputType.number,
                  inputFormatters: [FilteringTextInputFormatter.digitsOnly],
                  decoration: const InputDecoration(
                    labelText: 'MTU',
                    border: OutlineInputBorder(borderRadius: BorderRadius.zero),
                  ),
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: TextField(
                  controller: _keepalive,
                  keyboardType: TextInputType.number,
                  inputFormatters: [FilteringTextInputFormatter.digitsOnly],
                  decoration: const InputDecoration(
                    labelText: 'Keepalive (s)',
                    border: OutlineInputBorder(borderRadius: BorderRadius.zero),
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),
          Row(
            children: [
              Expanded(
                child: TextField(
                  controller: _dataShards,
                  keyboardType: TextInputType.number,
                  inputFormatters: [FilteringTextInputFormatter.digitsOnly],
                  decoration: const InputDecoration(
                    labelText: 'FEC 数据份数',
                    border: OutlineInputBorder(borderRadius: BorderRadius.zero),
                  ),
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: TextField(
                  controller: _parityShards,
                  keyboardType: TextInputType.number,
                  inputFormatters: [FilteringTextInputFormatter.digitsOnly],
                  decoration: const InputDecoration(
                    labelText: 'FEC 冗余份数',
                    border: OutlineInputBorder(borderRadius: BorderRadius.zero),
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),
          DropdownButtonFormField<String>(
            value: _compress,
            decoration: const InputDecoration(
              labelText: '压缩',
              border: OutlineInputBorder(borderRadius: BorderRadius.zero),
            ),
            items: const [
              DropdownMenuItem(value: '', child: Text('不压缩')),
              DropdownMenuItem(value: 'deflate', child: Text('deflate')),
              DropdownMenuItem(value: 'lz4', child: Text('lz4')),
              DropdownMenuItem(value: 'zstd', child: Text('zstd')),
            ],
            onChanged: (v) => setState(() => _compress = v ?? ''),
          ),
          const SizedBox(height: 12),
          TextField(
            controller: _obfuscate,
            decoration: const InputDecoration(
              labelText: '混淆密钥 obfuscate_key',
              hintText: '两端一致时启用数据特征混淆',
              border: OutlineInputBorder(borderRadius: BorderRadius.zero),
            ),
          ),
          const SizedBox(height: 12),

          _section('虚拟子网'),
          TextField(
            controller: _subnet,
            onChanged: (_) => setState(() {}),
            decoration: const InputDecoration(
              labelText: '虚拟子网 subnet',
              hintText: '如 10.10.0.0/16, 客户端需与服务端一致',
              border: OutlineInputBorder(borderRadius: BorderRadius.zero),
            ),
          ),
          const SizedBox(height: 12),

          if (isGateway) ...[
            _section('网关监听'),
            TextField(
              controller: _udpListen,
              maxLines: 2,
              decoration: const InputDecoration(
                labelText: 'UDP 监听 (每行一个, 如 0.0.0.0:19090)',
                border: OutlineInputBorder(borderRadius: BorderRadius.zero),
              ),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _tcpListen,
              maxLines: 2,
              decoration: const InputDecoration(
                labelText: 'TCP 监听 (每行一个)',
                border: OutlineInputBorder(borderRadius: BorderRadius.zero),
              ),
            ),
            const SizedBox(height: 12),
            SwitchListTile(
              title: const Text('passbyvpn (默认全局出口)'),
              value: _passbyvpn,
              onChanged: (v) => setState(() => _passbyvpn = v),
              contentPadding: EdgeInsets.zero,
            ),
            SwitchListTile(
              title: const Text('ignore_push (忽略推送路由/DNS)'),
              value: _ignorePush,
              onChanged: (v) => setState(() => _ignorePush = v),
              contentPadding: EdgeInsets.zero,
            ),
            SwitchListTile(
              title: const Text('c2c (允许客户端互访)'),
              value: _c2c,
              onChanged: (v) => setState(() => _c2c = v),
              contentPadding: EdgeInsets.zero,
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _pushroutes,
              maxLines: 2,
              decoration: const InputDecoration(
                labelText: '推送路由 pushroutes (每行一个)',
                border: OutlineInputBorder(borderRadius: BorderRadius.zero),
              ),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _pushdns,
              keyboardType: TextInputType.number,
              inputFormatters: [FilteringTextInputFormatter.digitsOnly],
              decoration: const InputDecoration(
                labelText: '推送 DNS pushdns',
                border: OutlineInputBorder(borderRadius: BorderRadius.zero),
              ),
            ),
            const SizedBox(height: 12),
          ],

          _section('Android VpnService'),
          // TUN 地址/前缀由 subnet 自动推导 (客户端=网络地址+2, 网关=网络地址+1),
          // 只读展示, 避免手工填写与服务端 subnet 不一致.
          InputDecorator(
            decoration: const InputDecoration(
              labelText: 'TUN 地址 (自动推导)',
              border: OutlineInputBorder(borderRadius: BorderRadius.zero),
              contentPadding: EdgeInsets.symmetric(
                horizontal: 12,
                vertical: 12,
              ),
            ),
            child: Text(_tunPreview().$1),
          ),
          const SizedBox(height: 12),
          TextField(
            controller: _routes,
            maxLines: 3,
            decoration: const InputDecoration(
              labelText: 'VPN 路由 routes (每行一个 CIDR)',
              hintText: '默认 0.0.0.0/0 全隧道; 也可只加 10.9.0.0/16 等',
              border: OutlineInputBorder(borderRadius: BorderRadius.zero),
            ),
          ),
          const SizedBox(height: 12),
          TextField(
            controller: _dns,
            maxLines: 2,
            decoration: const InputDecoration(
              labelText: 'DNS 服务器 (每行一个)',
              border: OutlineInputBorder(borderRadius: BorderRadius.zero),
            ),
          ),
          const SizedBox(height: 12),
          TextField(
            controller: _bypassroutes,
            maxLines: 2,
            decoration: const InputDecoration(
              labelText: '绕过 VPN 路由 bypassroutes (每行一个)',
              border: OutlineInputBorder(borderRadius: BorderRadius.zero),
            ),
          ),
          _section('测试连接'),
          TextField(
            controller: _testUrl,
            keyboardType: TextInputType.url,
            decoration: const InputDecoration(
              labelText: '测试 URL',
              hintText: '如 https://google.com, 用于运行页测量 VPN 延迟',
              border: OutlineInputBorder(borderRadius: BorderRadius.zero),
            ),
          ),
          const SizedBox(height: 24),
        ],
      ),
    );
  }

  Widget _section(String title) {
    return Padding(
      padding: const EdgeInsets.only(top: 16, bottom: 8),
      child: Text(
        title,
        style: Theme.of(context).textTheme.titleSmall?.copyWith(
          color: Theme.of(context).colorScheme.primary,
        ),
      ),
    );
  }
}
