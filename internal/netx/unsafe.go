package netx

import "unsafe"

func unsafePointer(b []byte) unsafe.Pointer { return unsafe.Pointer(&b[0]) }
