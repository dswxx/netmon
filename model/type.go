package model

import "time"

// ProcessStats 对应 eBPF Map 里的 Value
// 我们在 C 里也会定义同样的结构
type TrafficStats struct {
	TxBytes uint64
	RxBytes uint64
}

// ProcessEntity 是我们应用层使用的完整对象
type ProcessEntity struct {
	Pid      uint32
	Name     string
	IsAlive  bool      // 进程是否存活
	LastSeen time.Time // 最后一次活跃时间

	// 历史累计 (History / Right Panel)
	TxTotal uint64
	RxTotal uint64

	// 实时速率 (Realtime / Left Panel) - Bps (Bytes per second)
	TxRate uint64
	RxRate uint64

	// 内部记录：上一次的 Total，用来计算 Rate
	PrevTxTotal uint64
	PrevRxTotal uint64
}
