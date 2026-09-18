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
  late final TextEditingController _dohUrl = TextEditingController(
    text: c.dohUrl,
  );
  late final TextEditingController _directDns = TextEditingController(
    text: c.directDns,
  );
  late final TextEditingController _gfwlistUrl = TextEditingController(
    text: c.gfwlistUrl,
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
      _dohUrl,
      _directDns,
      _gfwlistUrl,
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
          ..bypassCn = _bypassCn
          ..routes = _lines(_routes.text)
          ..dns = _lines(_dns.text)
          ..testUrl = _testUrl.text.trim()
          ..dnsIntercept = _dnsIntercept
          ..dohUrl = _dohUrl.text.trim()
          ..directDns = _directDns.text.trim()
          ..gfwlistUrl = _gfwlistUrl.text.trim();
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
  late bool _bypassCn = c.bypassCn;
  late bool _dnsIntercept = c.dnsIntercept;

  /// 依据当前表单 subnet 预览自动推导的 TUN 地址/前缀.
  (String, int) _tunPreview() {
    final tmp =
        VpnConfig(id: '', name: '', mode: _mode)
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
        padding: const EdgeInsets.fromLTRB(12, 12, 12, 24),
        children: [
          _section('基本', [
            _textField(_name, label: '名称', hint: '如 家庭网关 / 公司服务器'),
            _dropdown<String>(
              value: _mode,
              label: '模式',
              items: const [
                DropdownMenuItem(value: 'client', child: Text('客户端 (Client)')),
                DropdownMenuItem(value: 'gateway', child: Text('网关 (Gateway)')),
              ],
              onChanged: (v) => setState(() => _mode = v ?? 'client'),
            ),
            if (!isGateway)
              _textField(
                _nexthop,
                label: 'Nexthop 服务器',
                hint: '如 1.2.3.4:19090 或 tcp://1.2.3.4:19090',
              ),
          ], subtitle: isGateway ? '网关模式无需填写 nexthop' : '客户端需填写对端服务器地址'),
          _section('密钥', [
            _textField(_privateKey, label: '本端私钥 private_key'),
            _textField(
              _publicKey,
              label: '对端公钥 public_key',
              hint: '服务器/网关的公钥 (base64), 客户端必填',
            ),
            _textField(_pkl, label: '对端公钥列表 pkl (每行一个)', maxLines: 3),
          ], subtitle: '本端私钥与对端公钥'),
          _section('传输参数', [
            _pair(
              _numberField(_mtu, label: 'MTU'),
              _numberField(_keepalive, label: 'Keepalive (s)'),
            ),
            _pair(
              _numberField(_dataShards, label: 'FEC 数据份数'),
              _numberField(_parityShards, label: 'FEC 冗余份数'),
            ),
            _dropdown<String>(
              value: _compress,
              label: '压缩',
              items: const [
                DropdownMenuItem(value: '', child: Text('不压缩')),
                DropdownMenuItem(value: 'deflate', child: Text('deflate')),
                DropdownMenuItem(value: 'lz4', child: Text('lz4')),
                DropdownMenuItem(value: 'zstd', child: Text('zstd')),
              ],
              onChanged: (v) => setState(() => _compress = v ?? ''),
            ),
            _textField(
              _obfuscate,
              label: '混淆密钥 obfuscate_key',
              hint: '两端一致时启用数据特征混淆',
            ),
          ], subtitle: '链路 MTU、保活、纠删码与压缩'),
          _section('虚拟子网', [
            _textField(
              _subnet,
              label: '虚拟子网 subnet',
              hint: '如 10.10.0.0/16, 客户端需与服务端一致',
              onChanged: (_) => setState(() {}),
            ),
            _readonlyField('TUN 地址 (自动推导)', _tunPreview().$1),
          ], subtitle: '客户端取网络地址+2, 网关取网络地址+1'),
          if (isGateway)
            _section('网关监听', [
              _textField(
                _udpListen,
                label: 'UDP 监听 (每行一个)',
                hint: '如 0.0.0.0:19090',
                maxLines: 2,
              ),
              _textField(_tcpListen, label: 'TCP 监听 (每行一个)', maxLines: 2),
            ], subtitle: '网关对外提供服务的监听地址'),
          if (isGateway)
            _section('网关推送与选项', [
              _textField(
                _pushroutes,
                label: '推送路由 pushroutes (每行一个)',
                hint: '下发给客户端的路由',
                maxLines: 2,
              ),
              _numberField(_pushdns, label: '推送 DNS pushdns'),
              _switch(
                title: 'passbyvpn (默认全局出口)',
                value: _passbyvpn,
                onChanged: (v) => setState(() => _passbyvpn = v),
              ),
              _switch(
                title: 'ignore_push (忽略推送路由/DNS)',
                value: _ignorePush,
                onChanged: (v) => setState(() => _ignorePush = v),
              ),
              _switch(
                title: 'c2c (允许客户端互访)',
                value: _c2c,
                onChanged: (v) => setState(() => _c2c = v),
              ),
            ], subtitle: '下发给客户端的路由/DNS 与网关行为开关'),
          _section('路由与 DNS', [
            _textField(
              _routes,
              label: 'VPN 路由 routes (每行一个 CIDR)',
              hint: '默认 0.0.0.0/0 全隧道; 也可只加 10.9.0.0/16 等',
              maxLines: 3,
            ),
            _textField(_dns, label: 'DNS 服务器 (每行一个)', maxLines: 2),
            _textField(
              _bypassroutes,
              label: '绕过 VPN 路由 bypassroutes (每行一个)',
              maxLines: 2,
            ),
            _switch(
              title: '绕过中国大陆 (中国 IP 直连)',
              subtitle: '拉取中国 IP 段, 仅非中国流量接入 VPN; 启用后每次启动自动更新缓存',
              value: _bypassCn,
              onChanged: (v) => setState(() => _bypassCn = v),
            ),
          ], subtitle: 'Android VpnService 建立 tun 时使用的路由与 DNS'),
          _section('DNS 拦截分流', [
            _switch(
              title: '启用 DNS 拦截分流',
              subtitle:
                  '拦截 tun 上 53 端口 DNS: 命中 gfwlist 的域名走 DoH 加密解析, '
                  '其余直连国内 DNS',
              value: _dnsIntercept,
              onChanged: (v) => setState(() => _dnsIntercept = v),
            ),
            if (_dnsIntercept) ...[
              _textField(
                _dohUrl,
                label: 'DoH 服务地址',
                hint: '如 https://1.1.1.1/dns-query',
                keyboardType: TextInputType.url,
              ),
              _textField(
                _directDns,
                label: '直连 DNS 服务器',
                hint: '如 114.114.114.114',
              ),
              _textField(
                _gfwlistUrl,
                label: 'gfwlist 下载地址',
                hint: '默认 GitHub gfwlist, 每日自动更新并缓存',
                keyboardType: TextInputType.url,
                maxLines: 2,
              ),
            ],
          ], subtitle: '命中 gfwlist 的域名走 DoH, 其余直连'),
          _section('测试连接', [
            _textField(
              _testUrl,
              label: '测试 URL',
              hint: '如 https://google.com',
              keyboardType: TextInputType.url,
            ),
          ], subtitle: '运行页据此测量 VPN 延迟'),
        ],
      ),
    );
  }

  /// 分组卡片: 同类配置集中放置, 子项之间统一留白.
  Widget _section(String title, List<Widget> children, {String? subtitle}) {
    final theme = Theme.of(context);
    return Card(
      margin: const EdgeInsets.only(bottom: 12),
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(
              title,
              style: theme.textTheme.titleSmall?.copyWith(
                color: theme.colorScheme.primary,
                fontWeight: FontWeight.bold,
              ),
            ),
            if (subtitle != null) ...[
              const SizedBox(height: 2),
              Text(
                subtitle,
                style: theme.textTheme.bodySmall?.copyWith(
                  color: theme.colorScheme.onSurfaceVariant,
                ),
              ),
            ],
            const SizedBox(height: 12),
            for (var i = 0; i < children.length; i++) ...[
              if (i > 0) const SizedBox(height: 12),
              children[i],
            ],
          ],
        ),
      ),
    );
  }

  Widget _textField(
    TextEditingController controller, {
    required String label,
    String? hint,
    int maxLines = 1,
    TextInputType? keyboardType,
    List<TextInputFormatter>? formatters,
    ValueChanged<String>? onChanged,
  }) {
    return TextField(
      controller: controller,
      maxLines: maxLines,
      keyboardType: keyboardType,
      inputFormatters: formatters,
      onChanged: onChanged,
      decoration: InputDecoration(labelText: label, hintText: hint),
    );
  }

  Widget _numberField(
    TextEditingController controller, {
    required String label,
  }) {
    return _textField(
      controller,
      label: label,
      keyboardType: TextInputType.number,
      formatters: [FilteringTextInputFormatter.digitsOnly],
    );
  }

  /// 只读展示 (外观与输入框一致).
  Widget _readonlyField(String label, String value) {
    return InputDecorator(
      decoration: InputDecoration(
        labelText: label,
        contentPadding: const EdgeInsets.symmetric(
          horizontal: 12,
          vertical: 12,
        ),
      ),
      child: Text(value),
    );
  }

  Widget _dropdown<T>({
    required T value,
    required String label,
    required List<DropdownMenuItem<T>> items,
    required ValueChanged<T?> onChanged,
  }) {
    return DropdownButtonFormField<T>(
      initialValue: value,
      isExpanded: true,
      decoration: InputDecoration(labelText: label),
      items: items,
      onChanged: onChanged,
    );
  }

  Widget _switch({
    required String title,
    String? subtitle,
    required bool value,
    required ValueChanged<bool> onChanged,
  }) {
    return SwitchListTile(
      title: Text(title),
      subtitle: subtitle == null ? null : Text(subtitle),
      value: value,
      onChanged: onChanged,
      contentPadding: EdgeInsets.zero,
    );
  }

  /// 并排两个等宽控件, 列间距与表单纵向间距一致.
  Widget _pair(Widget left, Widget right) {
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Expanded(child: left),
        const SizedBox(width: 12),
        Expanded(child: right),
      ],
    );
  }
}
