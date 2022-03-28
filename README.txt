基于现代c++的一个vpn实现

功能参数介绍，除--config参数之外，所有参数均可在命令行或配置文件中，在下
面一一解释各参数相关作用


--config	可配置一个参数配置文件，如vpn.conf，配置文件内容以key=value
	的ini配置文件的方式保存，如 identity=server。

--identity	指定avpn运行角色是server或client，avpn的客户端和服务器是同一
	程序，server或是client，主要由这个参数指定avpn的运行身份。

--tun		指定tun虚拟网卡名称，在windows上为虚拟网卡的具体名字（有时需
	要注意空格，比如 "以太网 3" 中间的空格不能丢失），在linux或其它系统
	平台可以不预先创建，avpn将会自动创建虚拟网卡。

--upstream	运行身份作为client时，这个参数指定了目标server和端口，目前版
	本实现由udp/tcp必须同时运行，所以需要同时指定udp和ws的地址和端口。如
	--upstream ws://example.com:33333 udp://example.com:33333

--tcp		运行身份作为server时，这个参数指定了监听的tcp地址和端口，一
	般如--tcp "[::0]:33333"表示tcp监听在ipv6地下::0下的33333端口，再如
	--tcp "0.0.0.0:33333"表示tcp监听在ipv4地下0.0.0.0下的33333端口。

--udp		运行身份作为server时，这个参数指定了监听的udp地址和端口，一
	般如--udp "[::0]:33333"表示udp监听在ipv6地下::0下的33333端口，再如
	--udp "0.0.0.0:33333"表示udp监听在ipv4地下0.0.0.0下的33333端口。

--data_shards
--parity_shards	这2个参数是fec参数，主要指定多少份data_shards和多少份parity_shards
	组成一组fec数据，也就是说，在发送data_shards份数据的同时，携带parity_shards
	份冗余数据。fec算法可以允许任意最多丢失parity_shards份数据。

--fec_delay	fec采集延迟，单位ms，这个参数控制fec在fec_delay设定的时间内
	读取到的网卡数据将做为一组fec数据，按照上面data_shards、parity_shards
	进行编码后再发送。通常这个参数不宜过大，否则会导致很大的延迟。

--autofec	自动化fec参数，暂未完成实现。

--mode		数据发送模式，取值0: 只用 udp, 1: tcp/udp 混合, 2: 只用 tcp主
	要由这3种模式。如果udp模式，则在延迟上一般远小于tcp，但是在udp丢包特别
	严重的ISP网络环境中，tcp有时更有效率.

--compress	启用数据压缩算法。

--keepalive	设置心跳时间间隔，单位ms。

--pushroute	推送路由到client，当运行身份为server时，向client推送路由。一
	般格式为"TARGET MASK GATEWAY METRIC"，其中METRIC可省略，也可以使用CIDR
	格式，如："TARGET/32 GATEWAY METRIC"。

--pushdns	推送DNS到client，暂未完成实现完全。

--passbyvpn	通过server配置此参数，所有client将默认所有流量将通过server传输。
	该参数暂未完成实现完全。

--subnet	在服务端上指定虚拟的子网网段，默认为"10.0.0.1/16"。

--c2c		是否允许client之间互相通过虚拟子网网络通信，默认是允许。

--controller	指定控制器的，控制器是一个用于通过本地websocket服务控制avpn
	开启或关闭，或者获取网络速率的，比如在flutter中开启一个websocket服务，
	服务端口为5656，那么启动avpn的时候使用 --controller 5656就可以让avpn自动
	连接到flutter中的服务，flutter通过websocket连接控制avpn.

--disable_logs	关闭日志写入.
