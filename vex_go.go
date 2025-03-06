package vex_go

/*
#cgo CFLAGS: -I./vex/pub -I./pyvex_c
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <setjmp.h>
#include <stddef.h>
#include <libvex.h>
#include "libvex.h"
#include "libvex_ir.h"
#include "pyvex.h"
*/
import "C"
import (
	"unsafe"
)

func VexInit() bool {
	r := C.vex_init()
	if r == 1 {
		return true
	}
	return false
}

func VexLift(v VexArch, mc []byte, insAddr int64) *C.VEXLiftResult {
	var vai C.VexArchInfo
	vai.endness = C.VexEndnessLE // 小端

	cData := (*C.uchar)(unsafe.Pointer(&mc[0]))
	r := C.vex_lift(C.VexArch(v), vai, cData, C.ulonglong(insAddr), C.uint(99), C.uint(4),
		C.int(1), C.int(0), C.int(0), C.int(1), C.int(0), C.int(1), C.int(0), C.VexRegUpdUnwindregsAtMemAccess, C.uint(0))

	return r
}

func GetStmtAt(stmts **C.IRStmt, idx int, maxIdx int) *IRStmt {
	if idx < 0 || idx >= maxIdx {
		return nil
	}

	// 将 IRStmt** 转换为切片
	stmtsSlice := (*[1 << 30]*C.IRStmt)(unsafe.Pointer(stmts))[:maxIdx:maxIdx]
	return (*IRStmt)(unsafe.Pointer(stmtsSlice[idx]))
}
