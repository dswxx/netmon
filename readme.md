# netmon 🌐

**netmon** 是一个基于 **eBPF** 的高性能 Linux 网络流量监控工具。
它在内核态实时统计 **进程级网络带宽**，并通过精美的终端 TUI 展示：

* 哪个进程正在耗你带宽
* TCP / UDP 发送与接收速率
* 峰值波形图
* 死亡进程的历史网络行为

得益于 **eBPF CO-RE** 技术，生成的二进制可跨内核版本运行（>= 5.8），无需重新编译。

---

## 📸 运行截图

![运行截图](./运行截图.png)

---

# ✨ 功能特性

* ⚡ **内核态实时监控**：基于 kprobe（`tcp_sendmsg`, `udp_sendmsg`, `tcp_cleanup_rbuf` 等）
* 🌐 **TCP / UDP 全覆盖**，含 QUIC、DNS、游戏流量等常见协议
* 🧹 **自动过滤回环流量**（127.0.0.1）
* 🧵 **多线程自动聚合**（如浏览器、下载器）
* 💀 **死亡进程保留历史行为**
* 📊 **专业级 TUI 仪表盘（榜单 + 波形图）**
* 📱 **自适应布局**

---

# 🛠️ 环境要求

| 项目           | 要求                 |
| ------------ | ------------------ |
| OS           | Linux              |
| 内核           | ≥ 5.8，支持 BTF       |
| 权限           | 需要 root            |
| Go 版本        | **≥ 1.24**（源码编译需要） |
| Clang / LLVM | 用于生成 eBPF 字节码      |

---

# 🚀 快速开始（推荐方式）

## **方式一：直接下载并运行 `netmon-static`（最简单）**

从 Release 页面下载：

👉 [https://github.com/dswxx/netmon/releases/tag/v1.0.0](https://github.com/dswxx/netmon/releases/tag/v1.0.0)

```bash
chmod +x netmon-static
sudo ./netmon-static
```

无需编译、不依赖 clang，也不需要 Go 环境。

---

# 🧑‍💻 方式二：从源码构建（开发者流程）

适合你要修改 eBPF C 或 Go 逻辑、调试、扩展功能时使用。

---

## ① 克隆项目

```bash
git clone https://github.com/dswxx/netmon.git
cd netmon
```

---

## ② 安装依赖（Ubuntu/Debian）

```bash
sudo apt update
sudo apt install -y clang llvm git linux-headers-$(uname -r)
```

安装 Go ≥ 1.24（推荐从官方包或使用 go install）：

```bash
sudo snap install go --classic
go version
```

---

## ③ 生成 eBPF 字节码（Go 自动调用 clang）

```bash
go generate
```

成功后生成：

```
bpf_bpfel.go
bpf_bpfeb.go
```

---

## ④ 编译 Go 程序

```bash
go build -o netmon
```

---

## ⑤ 运行

```bash
sudo ./netmon
```

---

# 🧳 方式三：构建便携版（可随身携带）

```bash
CGO_ENABLED=0 go build -ldflags "-w -s" -o netmon-static
```

得到的二进制无需依赖系统 libc，可直接运行。

---

# 🧩 技术架构

## **内核态（eBPF C 程序）**

挂载点：

* `tcp_sendmsg` —— TCP 发送
* `tcp_cleanup_rbuf` —— TCP 接收
* `udp_sendmsg` —— UDP 发送
* `udp_recvmsg` —— UDP 接收（Map-in-Map 技术）

技术特性：

* **CO-RE 跨内核兼容**
* **零拷贝统计逻辑**
* **极低开销、无需 socket hook**

---

## **用户态（Go 程序）**

负责：

* 线程 → 进程级聚合
* 获取 / 缓存进程名
* 速率计算
* TUI 渲染（基于 `termui`）

UI 包含：

* 实时速率榜单
* 历史速率榜单
* 波形图（含峰值）
* 屏幕大小自适应布局

---

# 📄 开源协议

MIT License

