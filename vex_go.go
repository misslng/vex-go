package vex_go

/*
#cgo CFLAGS: -I./vex/pub -I./pyvex_c
#cgo LDFLAGS: -lpyvex
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

func VexLift(v VexArch, mc []byte, insAddr uint64, en VexEndness) *IRSb {
	var vai C.VexArchInfo
	vai.endness = en

	cData := (*C.uchar)(unsafe.Pointer(&mc[0]))
	r := C.vex_lift(C.VexArch(v), vai, cData, C.ulonglong(insAddr), C.uint(99), C.uint(4),
		C.int(1), C.int(0), C.int(0), C.int(1), C.int(0), C.int(1), C.int(0), C.VexRegUpdUnwindregsAtMemAccess, C.uint(0))
	if r == nil {
		return nil
	}
	return (*IRSb)(unsafe.Pointer(r.irsb))
}
