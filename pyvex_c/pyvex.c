/*
This is shamelessly ripped from Vine, because those guys have very very strange language preferences.
Vine is Copyright (C) 2006-2009, BitBlaze Team.

You can redistribute and modify it under the terms of the GNU GPL,
version 2 or later, but it is made available WITHOUT ANY WARRANTY.
See the top-level README file for more details.

For more information about Vine and other BitBlaze software, see our
web site at: http://bitblaze.cs.berkeley.edu/
*/

//======================================================================
//
// This file provides the interface to VEX that allows block by block
// translation from binary to VEX IR.
//
//======================================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <stddef.h>
#include <libvex.h>

#include "pyvex.h"
#include "pyvex_internal.h"
#include "logging.h"

//======================================================================
//
// Globals
//
//======================================================================

// Some info required for translation
VexArchInfo         vai_host;
VexGuestExtents     vge;
VexTranslateArgs    vta;
VexTranslateResult  vtr;
VexAbiInfo	        vbi;
VexControl          vc;

// Log message buffer, from vex itself
char *msg_buffer = NULL;
size_t msg_capacity = 0, msg_current_size = 0;

jmp_buf jumpout;

//======================================================================
//
// Functions needed for the VEX translation
//
//======================================================================

#ifdef _MSC_VER
__declspec(noreturn)
#else
__attribute__((noreturn))
#endif
static void failure_exit(void) {
	longjmp(jumpout, 1);
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

void clear_log() {
	if (msg_buffer != NULL) {
			free(msg_buffer);
			msg_buffer = NULL;
			msg_capacity = 0;
			msg_current_size = 0;
	}
}

static Bool chase_into_ok(void *closureV, Addr addr64) {
	return False;
}

static UInt needs_self_check(void *callback_opaque, VexRegisterUpdates* pxControl, const VexGuestExtents *guest_extents) {
	return 0;
}

static void *dispatch(void) {
	return NULL;
}

// Prepare the VexArchInfo struct
static void vex_prepare_vai(VexArch arch, VexArchInfo *vai) {
	switch (arch) {
		case VexArchX86:
			vai->hwcaps =   VEX_HWCAPS_X86_MMXEXT |
							VEX_HWCAPS_X86_SSE1 |
							VEX_HWCAPS_X86_SSE2 |
							VEX_HWCAPS_X86_SSE3 |
							VEX_HWCAPS_X86_LZCNT;
			break;
		case VexArchAMD64:
			vai->hwcaps =   VEX_HWCAPS_AMD64_SSE3 |
							VEX_HWCAPS_AMD64_CX16 |
							VEX_HWCAPS_AMD64_LZCNT |
							VEX_HWCAPS_AMD64_AVX |
							VEX_HWCAPS_AMD64_RDTSCP |
							VEX_HWCAPS_AMD64_BMI |
							VEX_HWCAPS_AMD64_AVX2;
			break;
		case VexArchARM:
			vai->hwcaps = VEX_ARM_ARCHLEVEL(8) |
							VEX_HWCAPS_ARM_NEON |
							VEX_HWCAPS_ARM_VFP3;
			break;
		case VexArchARM64:
			vai->hwcaps = 0;
			vai->arm64_dMinLine_lg2_szB = 6;
			vai->arm64_iMinLine_lg2_szB = 6;
			break;
		case VexArchPPC32:
			vai->hwcaps =   VEX_HWCAPS_PPC32_F |
							VEX_HWCAPS_PPC32_V |
							VEX_HWCAPS_PPC32_FX |
							VEX_HWCAPS_PPC32_GX |
							VEX_HWCAPS_PPC32_VX |
							VEX_HWCAPS_PPC32_DFP |
							VEX_HWCAPS_PPC32_ISA2_07;
			vai->ppc_icache_line_szB = 32; // unsure if correct
			break;
		case VexArchPPC64:
			vai->hwcaps =   VEX_HWCAPS_PPC64_V |
							VEX_HWCAPS_PPC64_FX |
							VEX_HWCAPS_PPC64_GX |
							VEX_HWCAPS_PPC64_VX |
							VEX_HWCAPS_PPC64_DFP |
							VEX_HWCAPS_PPC64_ISA2_07;
			vai->ppc_icache_line_szB = 64; // unsure if correct
			break;
		case VexArchS390X:
			vai->hwcaps = 0;
			break;
		case VexArchMIPS32:
		case VexArchMIPS64:
			vai->hwcaps = VEX_PRID_COMP_CAVIUM;
			break;
		case VexArchRISCV64:
			vai->hwcaps = 0;
			break;
		default:
			pyvex_error("Invalid arch in vex_prepare_vai.\n");
			break;
	}
}

// Prepare the VexAbiInfo
static void vex_prepare_vbi(VexArch arch, VexAbiInfo *vbi) {
	// only setting the guest_stack_redzone_size for now
	// this attribute is only specified by the X86, AMD64 and PPC64 ABIs

	switch (arch) {
		case VexArchX86:
			vbi->guest_stack_redzone_size = 0;
			break;
		case VexArchAMD64:
			vbi->guest_stack_redzone_size = 128;
			break;
		case VexArchPPC64:
			vbi->guest_stack_redzone_size = 288;
			break;
		default:
			break;
	}
}

VEXLiftResult _lift_r;

//----------------------------------------------------------------------
// Main entry point. Do a lift.
//----------------------------------------------------------------------
VEXLiftResult *vex_lift(
		VexArch guest,
		VexArchInfo archinfo,
		unsigned char *insn_start,
		unsigned long long insn_addr,
		unsigned int max_insns,
		unsigned int max_bytes,
		int opt_level,
		int traceflags,
		int allow_arch_optimizations,
		int strict_block_end,
		int collect_data_refs,
		int load_from_ro_regions,
		int const_prop,
		VexRegisterUpdates px_control,
		unsigned int lookback) {
	VexRegisterUpdates pxControl = px_control;

	vex_prepare_vai(guest, &archinfo);
	vex_prepare_vbi(guest, &vbi);

	pyvex_debug("Guest arch: %d\n", guest);
	pyvex_debug("Guest arch hwcaps: %08x\n", archinfo.hwcaps);

	vta.archinfo_guest = archinfo;
	vta.arch_guest = guest;
	vta.abiinfo_both = vbi; // Set the vbi value

	vta.guest_bytes         = (UChar *)(insn_start);  // Ptr to actual bytes of start of instruction
	vta.guest_bytes_addr    = (Addr64)(insn_addr);
	vta.traceflags          = traceflags;

	vc.guest_max_bytes     = max_bytes;
	vc.guest_max_insns     = max_insns;
	vc.iropt_level         = opt_level;
	vc.lookback_amount     = lookback;

	// Gate all of these on one flag, they depend on the arch
	vc.arm_allow_optimizing_lookback = allow_arch_optimizations;
	vc.arm64_allow_reordered_writeback = allow_arch_optimizations;
	vc.x86_optimize_callpop_idiom = allow_arch_optimizations;

	vc.strict_block_end = strict_block_end;

	clear_log();

	// Do the actual translation
	if (setjmp(jumpout) == 0) {
		LibVEX_Update_Control(&vc);
		_lift_r.is_noop_block = False;
		_lift_r.data_ref_count = 0;
		_lift_r.const_val_count = 0;
		_lift_r.irsb = LibVEX_Lift(&vta, &vtr, &pxControl);
		if (!_lift_r.irsb) {
			// Lifting failed
			return NULL;
		}
		remove_noops(_lift_r.irsb);
		if (guest == VexArchMIPS32) {
			// This post processor may potentially remove statements.
			// Call it before we get exit statements and such.
			mips32_post_processor_fix_unconditional_exit(_lift_r.irsb);
		}
		get_exits_and_inst_addrs(_lift_r.irsb, &_lift_r);
		get_default_exit_target(_lift_r.irsb, &_lift_r);
		if (guest == VexArchARM && _lift_r.insts > 0) {
			arm_post_processor_determine_calls(_lift_r.inst_addrs[0], _lift_r.size, _lift_r.insts, _lift_r.irsb);
		}
		zero_division_side_exits(_lift_r.irsb);
		get_is_noop_block(_lift_r.irsb, &_lift_r);
		if (collect_data_refs || const_prop) {
			execute_irsb(_lift_r.irsb, &_lift_r, guest, (Bool)load_from_ro_regions, (Bool)collect_data_refs, (Bool)const_prop);
		}
		return &_lift_r;
	} else {
		return NULL;
	}
}
