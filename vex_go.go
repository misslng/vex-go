package vex_go

/*
#cgo CFLAGS: -I${SRCDIR}/vex/pub
#cgo LDFLAGS: -L${SRCDIR} -lvex
#include "libvex.h"
#include <stdlib.h>
#include <string.h>
char *msg_buffer = NULL;
size_t msg_capacity = 0, msg_current_size = 0;
__attribute__((noreturn)) static void failure_exit(void) {
	exit(1);
}
static void log_bytes(const HChar* bytes, SizeT nbytes) {
	if (msg_buffer == NULL) {
		msg_buffer = malloc(nbytes);
		msg_capacity = nbytes;
	}
	if (nbytes + msg_current_size > msg_capacity) {
		do {
			msg_capacity *= 2;
		} while (nbytes + msg_current_size > msg_capacity);
		msg_buffer = realloc(msg_buffer, msg_capacity);
	}

	memcpy(&msg_buffer[msg_current_size], bytes, nbytes);
	msg_current_size += nbytes;
}
static void vex_init(VexControl* vc) {  // vc 指向的就是 Go 的 vexControl
    LibVEX_Init(failure_exit, log_bytes, 0, vc);
}
*/
import "C"
import "runtime"

const (
	VexArchInvalid VexArch = C.VexArch_INVALID
	VexArchX86     VexArch = C.VexArchX86
	VexArchAMD64   VexArch = C.VexArchAMD64
	VexArchARM     VexArch = C.VexArchARM
	VexArchARM64   VexArch = C.VexArchARM64
	VexArchPPC32   VexArch = C.VexArchPPC32
	VexArchPPC64   VexArch = C.VexArchPPC64
	VexArchS390X   VexArch = C.VexArchS390X
	VexArchMIPS32  VexArch = C.VexArchMIPS32
	VexArchMIPS64  VexArch = C.VexArchMIPS64
	VexArchTILEGX  VexArch = C.VexArchTILEGX
	VexArchRISCV64 VexArch = C.VexArchRISCV64
)

const (
	VexEndnessInvalid VexEndness = C.VexEndness_INVALID
	VexEndnessLE      VexEndness = C.VexEndnessLE
	VexEndnessBE      VexEndness = C.VexEndnessBE
)

var (
	initialized        = false
	vexArchInfo        C.VexArchInfo
	vexGuestExtents    C.VexGuestExtents
	vexTranslateArgs   C.VexTranslateArgs
	vexTranslateResult C.VexTranslateResult
	vexAbiInfo         C.VexAbiInfo
	vexControl         C.VexControl
)

func VexInit() {
	if !initialized {
		C.LibVEX_default_VexControl(&vexControl)
		C.LibVEX_default_VexArchInfo(&vexArchInfo)
		C.LibVEX_default_VexAbiInfo(&vexAbiInfo)
		initialized = true
	} else {
		return
	}
	vexControl.iropt_verbosity = 0
	vexControl.iropt_level = 0 // No optimization by default
	//vc.iropt_precise_memory_exns    = False;
	vexControl.iropt_unroll_thresh = 0
	vexControl.guest_max_insns = 1 // By default, we vex 1 instruction at a time
	vexControl.guest_chase_thresh = 0
	vexControl.arm64_allow_reordered_writeback = 0
	vexControl.x86_optimize_callpop_idiom = 0
	vexControl.strict_block_end = 0
	vexControl.special_instruction_support = 0
	C.vex_init(&vexControl)

	// 使用时：
	if isLittleEndian() {
		vexArchInfo.endness = C.VexEndnessLE
	} else {
		vexArchInfo.endness = C.VexEndnessBE
	}
	vexAbiInfo.guest_stack_redzone_size = 0
	vexAbiInfo.guest_amd64_assume_fs_is_const = 1
	vexAbiInfo.guest_amd64_assume_gs_is_const = 1

	vexTranslateArgs.arch_guest = C.VexArch_INVALID // 后面再设置
	switch runtime.GOARCH {
	case "amd64":
		vexTranslateArgs.arch_host = C.VexArchAMD64
	case "386":
		vexTranslateArgs.arch_host = C.VexArchX86
	case "arm":
		vexTranslateArgs.arch_host = C.VexArchARM
		vexArchInfo.hwcaps = 7
	case "arm64":
		vexTranslateArgs.arch_host = C.VexArchARM64
	case "s390x":
		vexTranslateArgs.arch_host = C.VexArchS390X
		vexArchInfo.hwcaps = C.VEX_HWCAPS_S390X_LDISP
	case "ppc64":
		vexTranslateArgs.arch_host = C.VexArchPPC64
	case "riscv64":
		vexTranslateArgs.arch_host = C.VexArchRISCV64
	default:
		panic("Unsupported host arch")
	}
	vexTranslateArgs.archinfo_host = vexArchInfo

	//
	// The actual stuff to vex
	//
	vexTranslateArgs.guest_bytes = nil    // Set in vex_insts
	vexTranslateArgs.guest_bytes_addr = 0 // Set in vex_insts

	vexTranslateArgs.callback_opaque = nil
	vexTranslateArgs.preamble_function = nil
	vexTranslateArgs.instrument1 = nil
	vexTranslateArgs.instrument2 = nil
	vexTranslateArgs.finaltidy = nil

	vexTranslateArgs.guest_extents = &vexGuestExtents
	vexTranslateArgs.host_bytes = nil // Buffer for storing the output binary
	vexTranslateArgs.host_bytes_size = 0
	vexTranslateArgs.host_bytes_used = nil
	// doesn't exist? vta.do_self_check       = False;
	vexTranslateArgs.traceflags = 0 // Debug verbosity
	//vta.traceflags          = -1;                // Debug verbosity
	return
}
