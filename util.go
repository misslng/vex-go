package vex_go

import "unsafe"

func isLittleEndian() bool {
	var x uint16 = 0x1234
	return *(*byte)(unsafe.Pointer(&x)) == 0x34
}
