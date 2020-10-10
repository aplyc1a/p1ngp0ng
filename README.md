# p1ngp0ng                
轻量级ICMP C2工具                
                
# 依赖                
Linux环境与GCC套件。                
                
# 功能：                
**p1ng：**                
p1ng，实现C2服务器正向连接被控端。目前实现了对客户端的命令控制与文件上传下载。明文传输，未加密。                
                
**p0ng：**                
p0ng，实现被控端反向连接C2服务器。待开发。                
                
# 使用                
**p1ng：**                
p1ng -S -c ${client_ip}                
p1ng -C                
                
**p0ng：**                
待开发                
                