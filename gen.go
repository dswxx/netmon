package main

// 【修改】增加了 -cflags "-D__TARGET_ARCH_x86"
// 这告诉 C 代码我们是在 x86 架构上编译，从而正确启用 bpf_tracing.h 里的宏
// 如果你是 ARM 架构 (如 Mac M1/M2 Linux 虚拟机)，这里要改成 -D__TARGET_ARCH_arm64

//go:generate go tool bpf2go -target bpfel -cflags "-D__TARGET_ARCH_x86" -type traffic_stats bpf bpf/net_mon.c -- -I./headers
