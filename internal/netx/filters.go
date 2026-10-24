package netx

import (
	"net/netip"

	"golang.org/x/net/bpf"
)

func be32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// HostPairFilter passes Ethernet IPv4/UDP frames from src to dst, cut to snap bytes.
func HostPairFilter(src, dst netip.Addr, snap uint32) []bpf.Instruction {
	return []bpf.Instruction{
		bpf.LoadAbsolute{Off: 12, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipFalse: 7},
		bpf.LoadAbsolute{Off: 23, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 17, SkipFalse: 5},
		bpf.LoadAbsolute{Off: 26, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: be32(src), SkipFalse: 3},
		bpf.LoadAbsolute{Off: 30, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: be32(dst), SkipFalse: 1},
		bpf.RetConstant{Val: snap},
		bpf.RetConstant{Val: 0},
	}
}

// ServerQueryFilter passes IP packets (no link header) to or from server
// whose UDP payload starts with the connectionless 0xFFFFFFFF prefix.
func ServerQueryFilter(server netip.Addr) []bpf.Instruction {
	return []bpf.Instruction{
		bpf.LoadAbsolute{Off: 9, Size: 1},                                // 0 protocol
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 17, SkipFalse: 9},           // 1 -> 11 drop
		bpf.LoadAbsolute{Off: 6, Size: 2},                                // 2 fragment bits
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x3fff, SkipTrue: 7},      // 3 -> 11
		bpf.LoadAbsolute{Off: 12, Size: 4},                               // 4 source
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: be32(server), SkipTrue: 2},  // 5 -> 8
		bpf.LoadAbsolute{Off: 16, Size: 4},                               // 6 destination
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: be32(server), SkipFalse: 3}, // 7 -> 11
		bpf.LoadMemShift{Off: 0},                                         // 8 x = IP header length
		bpf.LoadIndirect{Off: 8, Size: 4},                                // 9 payload prefix
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xffffffff, SkipTrue: 1},    // 10 -> 12
		bpf.RetConstant{Val: 0},                                          // 11 drop
		bpf.RetConstant{Val: 4096},                                       // 12 accept
	}
}
