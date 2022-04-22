aVPN
====


aVPN是目前世界唯一基于 **现代c++** 的vpn实现，avpn展示了在现代c++的支持下，编写为数不多的代码，即实现一个功能完善且强大并跨各大主流平台的vpn，它不仅具有虚拟网络组建的功能，还能在丢包较高的环境下，通过纠错算法，保证通信的可靠。

<br>

***
<br>

### 开发环境要求：

<br>

1. 项目基于 **c++20** 开发，编译器要求gcc-10.3.1或更高，clang-13或更高，msvc-2019或更高.

1. cmake-3.20或更高.

***
<br>

### Linux 平台下编译:

<br>

首先执行git克隆源码

```
git clone <source url>
```
然后进入源码目录，执行如下操作：
```
mkdir build && cd build
```
```
cmake .. -DCMAKE_BUILD_TYPE=Debug
```

上面命令中，CMAKE_BUILD_TYPE=Debug指定了编译为Debug的类型，如果需要更好的性
能，则需要编译为Release.

在cmake命令成功执行完成后，开始输入以下命令编译：
```
make
```

通常编译过程不会出现问题，如果出现任何问题，请联系作者，并将完整的错误信息
保留并报告给作者。

成功编译后，可执行程序将在bin目录下生成.

***
<br>

### 部分选项介绍
<br>

avpn的cmake配置了默认编译选项参数，如果有必要，可以参考cmake源文件中的选
项开关尝试不同功能，比如可以选择使用mimalloc、tcmalloc等分配器，比如使用更快
的mold链接器，比如打开systemd的日志开关，便可将日志记录到systemd.journal中.

avpn还提供了一个更为简单的编译方式，在任何安装有docker环境下，进入avpn源码目
录，可以执行如下命令，创建一个docker并编译avpn：
```
docker build -t avpn:v1 .
```
编译完成后，将生成一个无任何系统依赖的avpn可执行程序，因为它使用了静态链接到
一个叫作 musl 的 libc，这样编译出来的avpn可执行程序将可运行在无glibc的环境下
如 initramfs 中，使用musl的最大好处就是可以无需关心系统上过于古老的glibc而导
致无法运行的问题。

***
<br>

### Windows 平台下编译

<br>
同样先执行git克隆源码，上面已经介绍过了，这里略过，在git克隆的源码目录下建立
一个build目录，然后执行以下命令：

```
cmake.exe ..
```

成功完成cmake后，cmake将生成vc的项目文件，然后执行以下命令编译avpn：
```
msbuild avpn.sln /p:Configuration="Debug"
```

在完成编译后，同样会生成一个avpn.exe在bin目录，当然也可以直接使用msvc打开
avpn.sln项目文件，通过菜单上的编译命令进行编译。

***
<br>

### 功能参数介绍
<br>

除config参数之外，所有参数均可在命令行或配置文件中，在下
面一一解释各参数相关作用

|  参    数      | 用法解释  |
|  --------      | -----    |
| config |		可配置一个参数配置文件，如vpn.conf，配置文件内容以key=value的ini配置文件的方式保存，如identity=server。|
| identity |		指定avpn运行角色是server或client，avpn的客户端和服务器是同一程序，server或是client，主要由这个参数指定avpn的运行身份。|
| tun |		指定tun虚拟网卡名称，在windows上为虚拟网卡的具体名字（有时需要注意空格，比如 "以太网 3" 中间的空格不能丢失），在类unix平台，avpn将会自动创建虚拟网卡，windows平台使用wintun同样也会自动创建虚拟网卡。|
| upstream |		运行身份作为client时，这个参数指定了目标server和端口，目前版本实现由udp/tcp必须同时运行，所以需要同时指定udp和ws的地址和端口。如--upstream ws://example.com:33333 udp://example.com:33333|
| socks_server |		这个参数指定avpn内部运行一个或多个socks server。|
| socks_interface |		内部运行socks server时，指定对外发起连接时，所bind的interface。|
| socks_userid<BR>socks_passwd |		指定socks server的userid/passwd。|
| tcp |		运行身份作为server时，这个参数指定了监听的tcp地址和端口，一般如--tcp "[::0]:33333"表示tcp监听在ipv6地下::0下的33333端口，再如--tcp "0.0.0.0:33333"表示tcp监听在ipv4地下0.0.0.0下的33333端口。|
| udp |		运行身份作为server时，这个参数指定了监听的udp地址和端口，一般如--udp "[::0]:33333"表示udp监听在ipv6地下::0下的33333端口，再如--udp "0.0.0.0:33333"表示udp监听在ipv4地下0.0.0.0下的33333端口。|
| data_shards <br> parity_shards |		这2个参数是fec参数，主要指定多少份data_shards和多少份parity_shards组成一组fec数据，也就是说，在发送data_shards份数据的同时，携带parity_shards份冗余数据。fec算法可以允许任意最多丢失parity_shards份数据。|
| fec_delay |		fec采集延迟，单位ms，这个参数控制fec在fec_delay设定的时间内读取到的网卡数据将做为一组fec数据，按照上面data_shards、parity_shards进行编码后再发送。通常这个参数不宜过大，否则会导致很大的延迟。|
| autofec |		自动化fec参数，暂未完成实现。|
| mode |		数据发送模式，取值0: 只用 udp，1: tcp/udp 混合，2: 只用 tcp主要由这3种模式。如果udp模式，则在延迟上一般远小于tcp，但是在udp丢包特别严重的ISP网络环境中，tcp有时更有效率。|
| compress |		启用数据压缩算法。|
| keepalive |		设置心跳时间间隔，单位ms。|
| pushroute |		推送路由到client，当运行身份为server时，向client推送路由。一般格式为"TARGET MASK GATEWAY METRIC"，其中METRIC可省略，也可以使用CIDR格式，如："TARGET/32 GATEWAY METRIC"。|
| pushdns |		推送DNS到client。|
| passbyvpn |		通过server配置此参数，所有client将默认所有流量将通过server传输。|
| subnet |		在服务端上指定虚拟的子网网段，默认为"10.0.0.1/16"。|
| c2c |		是否允许client之间互相通过虚拟子网网络通信，默认是允许。|
| controller |		指定控制器的，控制器是一个用于通过本地websocket服务控制avpn开启或关闭，或者获取网络速率的，比如在flutter中开启一个websocket服务，服务端口为5656，那么启动avpn的时候使用 --controller 5656就可以让avpn自动连接到flutter中的服务，flutter通过websocket连接控制avpn。|
| disable_logs |		关闭日志写入。|

