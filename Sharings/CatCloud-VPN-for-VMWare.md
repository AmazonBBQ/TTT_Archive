# 如何让 VMware 虚拟机走宿主机代理 VPN

## 背景说明

不同于传统的隧道型 VPN，本文讨论的是 **代理型 VPN**。

代理 VPN 只对支持代理协议的应用生效，例如：

- 浏览器
- curl
- 支持 HTTP/SOCKS 的程序

而不支持代理的协议（如 ICMP）仍然会直连物理网络。

例如：

```bash
curl ifconfig.me
```

在宿主机 terminal 中运行时，可能显示本机 IP，而不是 VPN IP。

后续提到的 VPN 均指 **本地代理模式 VPN**。

---

## 问题现象

开启 VPN 后：

- VMware 虚拟机使用 NAT 模式
- 虚拟机流量通过 VMware NAT 网关
- 再由宿主机物理网卡访问外网

结果：

👉 虚拟机对外仍表现为 **物理机 IP**

说明虚拟机没有成功走 VPN 代理。

---

## VPN 类型确认

点击 VPN 程序终端代理，得到：

```bash
export https_proxy=http://127.0.0.1:33210
http_proxy=http://127.0.0.1:33210
all_proxy=socks5://127.0.0.1:33211
```

可以确认：

- VPN 只监听 `127.0.0.1`
- 不接受 NAT 网关来源流量

因此虚拟机无法直接访问该代理。

---

## 初步尝试

在虚拟机中将代理地址改为：

```
物理机 NAT IP + 端口
```

测试结果：

- `ping` 成功
- `curl` 超时

原因：

- ping 使用 ICMP（网络层）
- curl 使用 HTTP（需要经过代理）

怀疑是 **防火墙阻止 TCP**。

---

## 端口测试

在宿主机 PowerShell 进行 TCP 测试后：

👉 确认端口被防火墙拦截。

---

## 解决方案：端口转发

思路：

把

```
127.0.0.1:33210
```

映射到

```
NAT IP:33210
```

这样虚拟机访问 NAT IP 时即可转发到 VPN。

---

### Windows 端口转发

```bash
netsh interface portproxy add v4tov4 listenaddress=192.168.239.1 listenport=33210 connectaddress=127.0.0.1 connectport=33210

netsh interface portproxy add v4tov4 listenaddress=192.168.239.1 listenport=33211 connectaddress=127.0.0.1 connectport=33211
```

---

### Windows 防火墙放行

```bash
New-NetFirewallRule -DisplayName "VM NAT VPN Proxy 33210" -Direction Inbound -LocalPort 33210 -Protocol TCP -Action Allow

New-NetFirewallRule -DisplayName "VM NAT VPN Proxy 33211" -Direction Inbound -LocalPort 33211 -Protocol TCP -Action Allow
```

---

## 虚拟机代理配置

编辑：

```bash
sudo vim /etc/environment
```

加入：

```bash
http_proxy="http://192.168.239.1:33210"
https_proxy="http://192.168.239.1:33210"
all_proxy="socks5://192.168.239.1:33211"
```

---

## 验证结果

在虚拟机 terminal：

```bash
curl ifconfig.me
```

显示 VPN IP，说明代理成功。

注意：

浏览器未变 IP 时，需要额外设置系统代理。

---

## 清理配置（可选）

删除端口转发：

```bash
netsh interface portproxy delete v4tov4 listenaddress=192.168.239.1 listenport=33210

netsh interface portproxy delete v4tov4 listenaddress=192.168.239.1 listenport=33211
```

删除防火墙规则：

```bash
Remove-NetFirewallRule -DisplayName "VM NAT VPN Proxy 33210"

Remove-NetFirewallRule -DisplayName "VM NAT VPN Proxy 33211"
```
