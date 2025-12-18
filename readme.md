# netmon 🌐

**netmon** 是一个基于 **eBPF** 的高性能 Linux 进程级网络流量监控工具。

它在内核态实时统计 **进程级应用层 payload 流量**（不含协议头开销），并通过 TUI 展示：

* 哪个进程占用你的带宽
* TCP / UDP 应用层数据的发送与接收速率（纯payload统计）
* 峰值波形图
* 死亡进程的历史网络活动

借助 **eBPF CO-RE** 技术，`netmon` 能够在不同 Linux 内核版本（≥ 5.8）跨平台运行，无需重新编译。

---

## 📸 运行截图

![运行截图](./运行截图.png)

---

# ✨ 功能特性

* ⚡ **内核态实时监控**（kprobe 钩子：`tcp_sendmsg`, `udp_sendmsg`, `tcp_cleanup_rbuf`, `udp_recvmsg`）
* 🌐 **覆盖 TCP / UDP 全协议流量**（含 QUIC/DNS 等）
* 🧹 **自动过滤回环流量**（127.0.0.1）
* 🧵 **线程聚合到进程级别展示**
* 📊 **专业级终端 UI：榜单 + 波形图**
* 📱 **自适应布局**

---

# 🛠️ 环境要求

| 项目           | 要求                  |
| ------------ | ------------------- |
| OS           | Linux               |
| 内核           | ≥ 5.8（需要 BTF）       |
| 权限           | root                |
| Go 版本        | **≥ 1.24**（仅源码构建需要） |
| Clang / LLVM | 构建 eBPF 字节码必需       |

---

# 🚀 运行方式（推荐）

## **方式一：Clone 后直接运行仓库内已提供的二进制**

仓库中已经提供：

```
netmon
netmon-static
```

执行：

```bash
git clone https://github.com/dswxx/netmon.git
cd netmon

# 赋予执行权限（如有需要）
chmod +x netmon netmon-static

# 推荐运行静态版（最兼容）
sudo ./netmon-static
# 或运行动态版
sudo ./netmon
```

特点：

* 无需构建
* 无需 Go 或 clang
* 对内核版本友好（CO-RE）
* `netmon-static` 可直接运行在大多数服务器上

---

# 🧑‍💻 方式二：从源码构建（开发者）

如果你要修改 eBPF 程序或 Go 代码，则使用此流程。

---

## ① 克隆仓库

```bash
git clone https://github.com/dswxx/netmon.git
cd netmon
```

---

## ② 安装依赖（Ubuntu / Debian）

```bash
sudo apt update
sudo apt install -y clang llvm linux-headers-$(uname -r) git
```

安装 Go（≥1.24）：

```bash
sudo snap install go --classic
go version
```

---

## ③ 生成 eBPF 字节码

Go 会自动调用 clang：

```bash
go generate
```

运行成功后会生成：

```
bpf_bpfel.go
bpf_bpfeb.go
```

---

## ④ 编译 Go 主程序

```bash
go build -o netmon
```

---

## ⑤ 运行

```bash
sudo ./netmon
```

---

# 🧩 技术架构

## **内核态（eBPF C）**

使用 kprobe 采集 L4 层数据：

* `tcp_sendmsg` —— TCP 发包
* `tcp_cleanup_rbuf` —— TCP 收包
* `udp_sendmsg` —— UDP 发包
* `udp_recvmsg` —— UDP 收包

---

## **用户态（Go）**

负责：

* 聚合线程 → 进程级展示
* 统计速率（B/s, KB/s, MB/s）
* 获取进程名 / comm 缓存
* 渲染终端 UI（基于 termui）
* 自适应布局、波形历史图

包含界面：

* 实时速率榜单
* 历史榜单
* 波形图（含峰值指示）

---

# 📄 开源协议

MIT License
可自由修改、分发和商业使用。

