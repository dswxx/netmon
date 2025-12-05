//go:build linux

package main

import (
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"netmon/model"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
)

// db 是我们的内存数据库，存储所有抓取到的进程信息
// Key: PID (uint32), Value: 进程详情指针
var db = make(map[uint32]*model.ProcessEntity)

// 历史数据切片 (用于绘制底部波形图)
// 初始化长度为 0，让图表从左向右自然生长，避免出现 "延迟感"
const historySize = 90 
var txHistory = make([]float64, 0)
var rxHistory = make([]float64, 0)

func main() {
	// 1. 移除内存锁定限制
	// eBPF map 需要锁定内存，Linux 默认限制很小 (64KB)，不移除会导致加载失败
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// 2. 加载 eBPF 字节码到内核
	// bpfObjects 是 bpf2go 工具根据 C 代码自动生成的结构体
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close() // 程序退出时卸载 BPF 程序

	// 3. 挂载内核钩子 (Hooks)
	// 我们分别在 TCP 和 UDP 的发送 (Send) 和接收 (Recv) 路径上挂载探针
	
	// TCP 发送 (kprobe/tcp_sendmsg)
	kpTx, _ := link.Kprobe("tcp_sendmsg", objs.KprobeTcpSendmsg, nil)
	defer kpTx.Close()

	// TCP 接收 (kprobe/tcp_cleanup_rbuf) - 当数据被用户态取走时触发
	kpRx, _ := link.Kprobe("tcp_cleanup_rbuf", objs.KprobeTcpCleanupRbuf, nil)
	defer kpRx.Close()

	// UDP 发送 (kprobe/udp_sendmsg)
	kpUdpTx, err:= link.Kprobe("udp_sendmsg", objs.KprobeUdpSendmsg, nil)
	if err != nil { log.Printf("udp tx error: %v", err) } else { defer kpUdpTx.Close() }

	// UDP 接收入口 (kprobe/udp_recvmsg) - 记录上下文 (PID -> Socket)
	kpUdpRx, err := link.Kprobe("udp_recvmsg", objs.KprobeUdpRecvmsg, nil)
	if err != nil { log.Printf("udp rx error: %v", err) } else { defer kpUdpRx.Close() }

	// UDP 接收出口 (kretprobe/udp_recvmsg) - 读取返回值 (Bytes)
	kpUdpRxRet, err := link.Kretprobe("udp_recvmsg", objs.KretprobeUdpRecvmsg, nil)
	if err != nil { log.Printf("udp rx ret error: %v", err) } else { defer kpUdpRxRet.Close() }

	// 4. 初始化 UI 系统 (TermUI)
	if err := ui.Init(); err != nil {
		log.Fatalf("failed to init termui: %v", err)
	}
	defer ui.Close()

	// ===========================
	// UI 组件定义
	// ===========================

	// [左上] 实时监控表格
	pLeft := widgets.NewTable()
	pLeft.Title = " [ 🟢 实时监控 (TCP+UDP Excl. Local) ] "
	pLeft.Rows = [][]string{{"PID", "进程名", "上传速率", "下载速率"}}
	pLeft.TextStyle = ui.NewStyle(ui.ColorWhite)
	pLeft.RowSeparator = false
	pLeft.BorderStyle.Fg = ui.ColorGreen

	// [右上] 历史统计表格
	pRight := widgets.NewTable()
	pRight.Title = " [ 📊 历史统计 (聚合) ] "
	pRight.Rows = [][]string{{"进程名", "发送总量", "接收总量"}}
	pRight.TextStyle = ui.NewStyle(ui.ColorWhite)
	pRight.RowSeparator = false
	pRight.BorderStyle.Fg = ui.ColorYellow

	// [左下] 上传波形图 (实心 Sparkline)
	slTx := widgets.NewSparkline()
	slTx.Data = txHistory
	slTx.LineColor = ui.ColorYellow 
	slTx.TitleStyle.Fg = ui.ColorYellow
	sgTx := widgets.NewSparklineGroup(slTx)
	sgTx.Title = " 上传趋势 " // 后续会动态更新标题带数据
	sgTx.BorderStyle.Fg = ui.ColorYellow

	// [右下] 下载波形图 (实心 Sparkline)
	slRx := widgets.NewSparkline()
	slRx.Data = rxHistory
	slRx.LineColor = ui.ColorGreen
	slRx.TitleStyle.Fg = ui.ColorGreen
	sgRx := widgets.NewSparklineGroup(slRx)
	sgRx.Title = " 下载趋势 "
	sgRx.BorderStyle.Fg = ui.ColorGreen

	// ===========================
	// 布局管理 (Grid)
	// ===========================
	grid := ui.NewGrid()
	termWidth, termHeight := ui.TerminalDimensions()
	grid.SetRect(0, 0, termWidth, termHeight)

	// 定义响应式布局：
	// 屏幕垂直切成 2 份
	// Row 1 (65%): 表格区（汇总信息已整合到表格底部）
	// Row 2 (35%): 图表区
	grid.Set(
		ui.NewRow(0.65,
			ui.NewCol(0.5, pLeft),
			ui.NewCol(0.5, pRight),
		),
		ui.NewRow(0.35,
			ui.NewCol(0.5, sgTx),
			ui.NewCol(0.5, sgRx),
		),
	)

	// 5. 事件循环与定时刷新
	uiEvents := ui.PollEvents()
	ticker := time.NewTicker(1 * time.Second) // 1秒刷新一次
	defer ticker.Stop()

	for {
		select {
		case e := <-uiEvents:
			// 按 q 或 Ctrl+C 退出
			if e.Type == ui.KeyboardEvent && (e.ID == "q" || e.ID == "<C-c>") {
				return
			}
			// 窗口大小改变时，重新计算布局
			if e.Type == ui.ResizeEvent {
				payload := e.Payload.(ui.Resize)
				grid.SetRect(0, 0, payload.Width, payload.Height)
				ui.Clear()
				ui.Render(grid)
			}
		case <-ticker.C:
			// A. 数据同步：从内核 Map 读取数据到 Go 内存
			syncData(&objs)
			// B. UI 更新：计算排序、汇总、更新组件内容
			updateUI(pLeft, pRight, slTx, sgTx, slRx, sgRx)
			// C. 渲染：画到屏幕上
			ui.Render(grid)
		}
	}
}

// syncData: 核心数据清洗逻辑
func syncData(objs *bpfObjects) {
	// 临时结构体：用于把同一 PID 下不同线程 (Thread) 的流量聚合在一起
	type aggStats struct { Tx uint64; Rx uint64; Names []string }
	snapshot := make(map[uint32]*aggStats)

	var key bpfProcessKey
	var stats bpfTrafficStats
	iter := objs.ProcStats.Iterate()

	// 1. 遍历 BPF Map，做初步聚合
	for iter.Next(&key, &stats) {
		pid := key.Pid
		if _, ok := snapshot[pid]; !ok { snapshot[pid] = &aggStats{} }
		s := snapshot[pid]
		s.Tx += stats.TxBytes
		s.Rx += stats.RxBytes
		name := parseComm(key.Comm)
		if name != "" { s.Names = append(s.Names, name) }
	}

	// 2. 更新内存数据库 (DB)
	for pid, s := range snapshot {
		if _, exists := db[pid]; !exists {
			db[pid] = &model.ProcessEntity{Pid: pid, IsAlive: true, LastSeen: time.Now()}
		}
		entity := db[pid]

		// 名字决策逻辑：优先用 /proc (权威)，其次用 BPF 历史记录 (兜底)
		if entity.Name == "" || entity.Name == "unknown" || entity.Name == "Socket Thread" {
			procName := getProcComm(pid)
			if procName != "" {
				entity.Name = procName
			} else {
				bestName := "unknown"
				// 简单的启发式算法：选一个不像线程名的名字
				for _, n := range s.Names {
					if n != "" && n != "unknown" && n != "Socket Thread" && !strings.HasPrefix(n, "DNS Res") {
						bestName = n
						break
					}
					if bestName == "unknown" && n != "" { bestName = n }
				}
				entity.Name = bestName
			}
		}

		// 计算瞬时速率 (Rate = CurrentTotal - PreviousTotal)
		entity.TxRate = 0
		entity.RxRate = 0
		if s.Tx >= entity.PrevTxTotal { entity.TxRate = s.Tx - entity.PrevTxTotal } else { entity.TxRate = s.Tx }
		if s.Rx >= entity.PrevRxTotal { entity.RxRate = s.Rx - entity.PrevRxTotal } else { entity.RxRate = s.Rx }

		// 更新总量和状态
		entity.TxTotal = s.Tx
		entity.RxTotal = s.Rx
		entity.PrevTxTotal = s.Tx
		entity.PrevRxTotal = s.Rx
		entity.LastSeen = time.Now()
		entity.IsAlive = true 
	}
}

// updateUI: 负责将数据格式化并填入 UI 组件
func updateUI(left *widgets.Table, right *widgets.Table,
              slTx *widgets.Sparkline, sgTx *widgets.SparklineGroup,
              slRx *widgets.Sparkline, sgRx *widgets.SparklineGroup) {
	
	var activeProcs []*model.ProcessEntity
	var totalTxRate, totalRxRate, totalHistoryTx, totalHistoryRx uint64

	// 1. 统计全局总数
	for _, p := range db {
		if p.TxRate > 0 || p.RxRate > 0 {
			activeProcs = append(activeProcs, p)
			totalTxRate += p.TxRate
			totalRxRate += p.RxRate
		}
		totalHistoryTx += p.TxTotal
		totalHistoryRx += p.RxTotal
	}

	// 2. 更新图表数据
	// 动态增长逻辑：不需要切除头部，直到达到 historySize
	// 这样图表会从左边开始自然生长，没有延迟感
	if len(txHistory) >= historySize {
		txHistory = txHistory[1:]
		rxHistory = rxHistory[1:]
	}
	txHistory = append(txHistory, float64(totalTxRate))
	rxHistory = append(rxHistory, float64(totalRxRate))

	// 计算峰值用于标题展示
	maxTx := 0.0
	maxRx := 0.0
	for _, v := range txHistory { if v > maxTx { maxTx = v } }
	for _, v := range rxHistory { if v > maxRx { maxRx = v } }

	slTx.Data = txHistory
	slRx.Data = rxHistory
	
	// 富文本标题：带实时数据
	sgTx.Title = fmt.Sprintf(" 上传趋势 (实时: %s/s | 峰值: %s/s) ", 
		formatBytes(totalTxRate), formatBytes(uint64(maxTx)))
	
	sgRx.Title = fmt.Sprintf(" 下载趋势 (实时: %s/s | 峰值: %s/s) ", 
		formatBytes(totalRxRate), formatBytes(uint64(maxRx)))

	// 3. 更新左表格 (实时列表 - 按速率排序)
	sort.SliceStable(activeProcs, func(i, j int) bool {
		rateI := activeProcs[i].TxRate + activeProcs[i].RxRate
		rateJ := activeProcs[j].TxRate + activeProcs[j].RxRate
		if rateI == rateJ { return activeProcs[i].Pid < activeProcs[j].Pid }
		return rateI > rateJ
	})
	left.Rows = [][]string{{"PID", "进程名", "上传速率", "下载速率"}}
	for _, p := range activeProcs {
		left.Rows = append(left.Rows, []string{
			fmt.Sprintf("%d", p.Pid),
			p.Name,
			formatBytes(p.TxRate) + "/s",
			formatBytes(p.RxRate) + "/s",
		})
	}
	
	// 计算需要插入的空行数量，让汇总行固定在底部
	// 关键改进：要确保分隔行和汇总行始终可见，所以要预留空间
	tableHeight := left.Inner.Dy()
	dataRows := len(activeProcs)
	reservedRows := 3  // 标题(1) + 分隔(1) + 汇总(1)
	
	// 如果数据行+预留行超过表格高度，则不添加空行
	// 这样即使数据很多，汇总行也会在底部可见（表格滚动）
	if dataRows + reservedRows < tableHeight {
		emptyRows := tableHeight - dataRows - reservedRows
		// 插入空行（使用空格填充每列，避免显示竖线）
		for i := 0; i < emptyRows; i++ {
			left.Rows = append(left.Rows, []string{" ", " ", " ", " "})
		}
	}
	
	// 添加分隔行和汇总信息
	left.Rows = append(left.Rows, []string{"━━━━", "━━━━━━━━", "━━━━━━━━", "━━━━━━━━"})
	left.Rows = append(left.Rows, []string{
		fmt.Sprintf("活跃进程: %d", len(activeProcs)),
		"实时总计",
		fmt.Sprintf("▲ %s/s", formatBytes(totalTxRate)),
		fmt.Sprintf("▼ %s/s", formatBytes(totalRxRate)),
	})

	// 4. 更新右表格 (历史列表 - 按总量排序)
	type historyItem struct { Name string; TxTotal uint64; RxTotal uint64 }
	historyMap := make(map[string]*historyItem)
	for _, p := range db {
		// 去除 (dead) 后缀进行聚合
		cleanName := strings.TrimSuffix(p.Name, " (dead)")
		if _, ok := historyMap[cleanName]; !ok { historyMap[cleanName] = &historyItem{Name: cleanName} }
		item := historyMap[cleanName]; item.TxTotal += p.TxTotal; item.RxTotal += p.RxTotal
	}
	var historyList []*historyItem
	for _, item := range historyMap { historyList = append(historyList, item) }
	
	sort.SliceStable(historyList, func(i, j int) bool {
		totalI := historyList[i].TxTotal + historyList[i].RxTotal
		totalJ := historyList[j].TxTotal + historyList[j].RxTotal
		if totalI == totalJ { return historyList[i].Name < historyList[j].Name }
		return totalI > totalJ
	})
	right.Rows = [][]string{{"进程名", "发送总量", "接收总量"}}
	for _, item := range historyList {
		right.Rows = append(right.Rows, []string{
			item.Name,
			formatBytes(item.TxTotal),
			formatBytes(item.RxTotal),
		})
	}
	
	// 计算需要插入的空行数量，让汇总行固定在底部
	rightTableHeight := right.Inner.Dy()
	rightDataRows := len(historyList)
	rightReservedRows := 3  // 标题(1) + 分隔(1) + 汇总(1)
	
	// 如果数据行+预留行超过表格高度，则不添加空行
	if rightDataRows + rightReservedRows < rightTableHeight {
		rightEmptyRows := rightTableHeight - rightDataRows - rightReservedRows
		// 插入空行（使用空格填充，避免显示竖线）
		for i := 0; i < rightEmptyRows; i++ {
			right.Rows = append(right.Rows, []string{" ", " ", " "})
		}
	}
	
	// 添加分隔行和汇总信息
	right.Rows = append(right.Rows, []string{"━━━━━━━━━━", "━━━━━━━━", "━━━━━━━━"})
	right.Rows = append(right.Rows, []string{
		fmt.Sprintf("历史记录: %d", len(historyList)),
		fmt.Sprintf("▲ %s", formatBytes(totalHistoryTx)),
		fmt.Sprintf("▼ %s", formatBytes(totalHistoryRx)),
	})
}

// 辅助函数：格式化字节单位 (B -> KB -> MB)
func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit { return fmt.Sprintf("%d B", b) }
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit { div *= unit; exp++ }
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// 辅助函数：从 /proc 读取进程名
func getProcComm(pid uint32) string {
	path := fmt.Sprintf("/proc/%d/comm", pid)
	data, err := os.ReadFile(path)
	if err != nil { return "" }
	if len(data) > 0 && data[len(data)-1] == '\n' { return string(data[:len(data)-1]) }
	return string(data)
}

// 辅助函数：解析 C 语言传来的 [16]int8 字符串
func parseComm(chars [16]int8) string {
	var buf []byte
	for _, v := range chars { if v == 0 { break }; buf = append(buf, byte(v)) }
	return string(buf)
}
