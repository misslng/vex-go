package vex_go

/*
#cgo CFLAGS: -I${SRCDIR}/vex/pub -I${SRCDIR}/pyvex_c
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

// VexEndness represents the endianness type
type VexEndness uint32

// VexArch represents the architecture type
type VexArch uint32

type IRStmtTag uint32

const (
	IstNoOp    IRStmtTag = 0x1E00 // 7680
	IstIMark   IRStmtTag = 0x1E01 // 7681
	IstAbiHint IRStmtTag = 0x1E02 // 7682
	IstPut     IRStmtTag = 0x1E03 // 7683
	IstPutI    IRStmtTag = 0x1E04 // 7684
	IstWrTmp   IRStmtTag = 0x1E05 // 7685
	IstStore   IRStmtTag = 0x1E06 // 7686
	IstLoadG   IRStmtTag = 0x1E07 // 7687
	IstStoreG  IRStmtTag = 0x1E08 // 7688
	IstCAS     IRStmtTag = 0x1E09 // 7689
	IstLLSC    IRStmtTag = 0x1E0A // 7690
	IstDirty   IRStmtTag = 0x1E0B // 7691
	IstMBE     IRStmtTag = 0x1E0C // 7692
	IstExit    IRStmtTag = 0x1E0D // 7693
)

// IRExprTag 表示 VEX IR 表达式的类型
type IRExprTag uint32
type IRTemp uint32

const (
	IexBinder IRExprTag = 0x1900 + iota // 用于 VEX 内部模式匹配的绑定器
	IexGet                              // 从固定偏移读取寄存器
	IexGetI                             // 从非固定偏移读取寄存器（数组访问）
	IexRdTmp                            // 读取临时变量
	IexQop                              // 四元运算
	IexTriop                            // 三元运算
	IexBinop                            // 二元运算
	IexUnop                             // 一元运算
	IexLoad                             // 内存加载
	IexConst                            // 常量
	IexITE                              // if-then-else 表达式
	IexCCall                            // 调用 C 函数
	IexVECRET                           // 向量返回值
	IexGSPTR                            // 获取状态指针
)

type IRType uint32

const (
	ItyINVALID IRType = 0x1100 + iota
	ItyI1             // 1位整数
	ItyI8             // 8位整数
	ItyI16            // 16位整数
	ItyI32            // 32位整数
	ItyI64            // 64位整数
	ItyI128           // 128位标量
	ItyF16            // 16位浮点数
	ItyF32            // IEEE 754 单精度浮点数
	ItyF64            // IEEE 754 双精度浮点数
	ItyD32            // 32位十进制浮点数
	ItyD64            // 64位十进制浮点数
	ItyD128           // 128位十进制浮点数
	ItyF128           // 128位浮点数（具体实现由平台定义）
	ItyV128           // 128位 SIMD
	ItyV256           // 256位 SIMD
)

type IRConstTag uint32

const (
	IcoU1 IRConstTag = iota
	IcoU8
	IcoU16
	IcoU32
	IcoU64
	IcoF32
	IcoF32i
	IcoF64
	IcoF64i
	IcoV128
	IcoV256
)

type IRConst struct {
	Tag   IRConstTag
	Value unsafe.Pointer
}

type IRJumpKind uint32

// IROp 表示VEX IR的操作码类型
type IROp uint32

const (
	// 基本操作码从0x1400开始
	IopINVALID IROp = 0x1400

	// 算术操作 - 加法
	IopAdd8  IROp = 0x1400 + 1
	IopAdd16 IROp = 0x1400 + 2
	IopAdd32 IROp = 0x1400 + 3
	IopAdd64 IROp = 0x1400 + 4

	// 算术操作 - 减法
	IopSub8  IROp = 0x1400 + 5
	IopSub16 IROp = 0x1400 + 6
	IopSub32 IROp = 0x1400 + 7
	IopSub64 IROp = 0x1400 + 8

	// 算术操作 - 乘法（无符号）
	IopMul8  IROp = 0x1400 + 9
	IopMul16 IROp = 0x1400 + 10
	IopMul32 IROp = 0x1400 + 11
	IopMul64 IROp = 0x1400 + 12

	// 位操作 - 或运算
	IopOr8  IROp = 0x1400 + 13
	IopOr16 IROp = 0x1400 + 14
	IopOr32 IROp = 0x1400 + 15
	IopOr64 IROp = 0x1400 + 16

	// 位操作 - 与运算
	IopAnd8  IROp = 0x1400 + 17
	IopAnd16 IROp = 0x1400 + 18
	IopAnd32 IROp = 0x1400 + 19
	IopAnd64 IROp = 0x1400 + 20

	// 位操作 - 异或运算
	IopXor8  IROp = 0x1400 + 21
	IopXor16 IROp = 0x1400 + 22
	IopXor32 IROp = 0x1400 + 23
	IopXor64 IROp = 0x1400 + 24

	// 位操作 - 左移
	IopShl8  IROp = 0x1400 + 25
	IopShl16 IROp = 0x1400 + 26
	IopShl32 IROp = 0x1400 + 27
	IopShl64 IROp = 0x1400 + 28

	// 位操作 - 右移（逻辑）
	IopShr8  IROp = 0x1400 + 29
	IopShr16 IROp = 0x1400 + 30
	IopShr32 IROp = 0x1400 + 31
	IopShr64 IROp = 0x1400 + 32

	// 位操作 - 右移（算术）
	IopSar8  IROp = 0x1400 + 33
	IopSar16 IROp = 0x1400 + 34
	IopSar32 IROp = 0x1400 + 35
	IopSar64 IROp = 0x1400 + 36

	// 整数比较 - 等于
	IopCmpEQ8  IROp = 0x1400 + 37
	IopCmpEQ16 IROp = 0x1400 + 38
	IopCmpEQ32 IROp = 0x1400 + 39
	IopCmpEQ64 IROp = 0x1400 + 40

	// 整数比较 - 不等于
	IopCmpNE8  IROp = 0x1400 + 41
	IopCmpNE16 IROp = 0x1400 + 42
	IopCmpNE32 IROp = 0x1400 + 43
	IopCmpNE64 IROp = 0x1400 + 44

	// 一元操作 - 非运算
	IopNot8  IROp = 0x1400 + 45
	IopNot16 IROp = 0x1400 + 46
	IopNot32 IROp = 0x1400 + 47
	IopNot64 IROp = 0x1400 + 48
)

// ARM64RegisterOffsets 包含ARM64寄存器名称到偏移值的映射
var ARM64RegisterOffsets = map[string]int{
	// 64位通用寄存器 X0-X30
	"X0": 16, "x0": 16, "W0": 16, "w0": 16,
	"X1": 24, "x1": 24, "W1": 24, "w1": 24,
	"X2": 32, "x2": 32, "W2": 32, "w2": 32,
	"X3": 40, "x3": 40, "W3": 40, "w3": 40,
	"X4": 48, "x4": 48, "W4": 48, "w4": 48,
	"X5": 56, "x5": 56, "W5": 56, "w5": 56,
	"X6": 64, "x6": 64, "W6": 64, "w6": 64,
	"X7": 72, "x7": 72, "W7": 72, "w7": 72,
	"X8": 80, "x8": 80, "W8": 80, "w8": 80,
	"X9": 88, "x9": 88, "W9": 88, "w9": 88,
	"X10": 96, "x10": 96, "W10": 96, "w10": 96,
	"X11": 104, "x11": 104, "W11": 104, "w11": 104,
	"X12": 112, "x12": 112, "W12": 112, "w12": 112,
	"X13": 120, "x13": 120, "W13": 120, "w13": 120,
	"X14": 128, "x14": 128, "W14": 128, "w14": 128,
	"X15": 136, "x15": 136, "W15": 136, "w15": 136,
	"X16": 144, "x16": 144, "W16": 144, "w16": 144,
	"X17": 152, "x17": 152, "W17": 152, "w17": 152,
	"X18": 160, "x18": 160, "W18": 160, "w18": 160,
	"X19": 168, "x19": 168, "W19": 168, "w19": 168,
	"X20": 176, "x20": 176, "W20": 176, "w20": 176,
	"X21": 184, "x21": 184, "W21": 184, "w21": 184,
	"X22": 192, "x22": 192, "W22": 192, "w22": 192,
	"X23": 200, "x23": 200, "W23": 200, "w23": 200,
	"X24": 208, "x24": 208, "W24": 208, "w24": 208,
	"X25": 216, "x25": 216, "W25": 216, "w25": 216,
	"X26": 224, "x26": 224, "W26": 224, "w26": 224,
	"X27": 232, "x27": 232, "W27": 232, "w27": 232,
	"X28": 240, "x28": 240, "W28": 240, "w28": 240,
	"X29": 248, "x29": 248, "W29": 248, "w29": 248, "FP": 248, "fp": 248, // Frame Pointer
	"X30": 256, "x30": 256, "W30": 256, "w30": 256, "LR": 256, "lr": 256, // Link Register

	// 特殊寄存器
	"SP": 264, "sp": 264, "XSP": 264, "xsp": 264, "WSP": 264, "wsp": 264, // Stack Pointer
	"PC": 272, "pc": 272, "XPC": 272, "xpc": 272, // Program Counter

	// 条件标志相关
	"CC_OP": 280, "cc_op": 280,
	"CC_DEP1": 288, "cc_dep1": 288,
	"CC_DEP2": 296, "cc_dep2": 296,
	"CC_NDEP": 304, "cc_ndep": 304,

	// 线程寄存器
	"TPIDR_EL0": 312, "tpidr_el0": 312,

	// SIMD/FP寄存器 (Q0-Q31, 128位每个)
	// 每个SIMD寄存器有多种视图: Q(128位), D(64位), S(32位), H(16位), B(8位)
	"Q0": 320, "q0": 320, "D0": 320, "d0": 320, "S0": 320, "s0": 320, "H0": 320, "h0": 320, "B0": 320, "b0": 320,
	"Q1": 336, "q1": 336, "D1": 336, "d1": 336, "S1": 336, "s1": 336, "H1": 336, "h1": 336, "B1": 336, "b1": 336,
	"Q2": 352, "q2": 352, "D2": 352, "d2": 352, "S2": 352, "s2": 352, "H2": 352, "h2": 352, "B2": 352, "b2": 352,
	"Q3": 368, "q3": 368, "D3": 368, "d3": 368, "S3": 368, "s3": 368, "H3": 368, "h3": 368, "B3": 368, "b3": 368,
	"Q4": 384, "q4": 384, "D4": 384, "d4": 384, "S4": 384, "s4": 384, "H4": 384, "h4": 384, "B4": 384, "b4": 384,
	"Q5": 400, "q5": 400, "D5": 400, "d5": 400, "S5": 400, "s5": 400, "H5": 400, "h5": 400, "B5": 400, "b5": 400,
	"Q6": 416, "q6": 416, "D6": 416, "d6": 416, "S6": 416, "s6": 416, "H6": 416, "h6": 416, "B6": 416, "b6": 416,
	"Q7": 432, "q7": 432, "D7": 432, "d7": 432, "S7": 432, "s7": 432, "H7": 432, "h7": 432, "B7": 432, "b7": 432,
	"Q8": 448, "q8": 448, "D8": 448, "d8": 448, "S8": 448, "s8": 448, "H8": 448, "h8": 448, "B8": 448, "b8": 448,
	"Q9": 464, "q9": 464, "D9": 464, "d9": 464, "S9": 464, "s9": 464, "H9": 464, "h9": 464, "B9": 464, "b9": 464,
	"Q10": 480, "q10": 480, "D10": 480, "d10": 480, "S10": 480, "s10": 480, "H10": 480, "h10": 480, "B10": 480, "b10": 480,
	"Q11": 496, "q11": 496, "D11": 496, "d11": 496, "S11": 496, "s11": 496, "H11": 496, "h11": 496, "B11": 496, "b11": 496,
	"Q12": 512, "q12": 512, "D12": 512, "d12": 512, "S12": 512, "s12": 512, "H12": 512, "h12": 512, "B12": 512, "b12": 512,
	"Q13": 528, "q13": 528, "D13": 528, "d13": 528, "S13": 528, "s13": 528, "H13": 528, "h13": 528, "B13": 528, "b13": 528,
	"Q14": 544, "q14": 544, "D14": 544, "d14": 544, "S14": 544, "s14": 544, "H14": 544, "h14": 544, "B14": 544, "b14": 544,
	"Q15": 560, "q15": 560, "D15": 560, "d15": 560, "S15": 560, "s15": 560, "H15": 560, "h15": 560, "B15": 560, "b15": 560,
	"Q16": 576, "q16": 576, "D16": 576, "d16": 576, "S16": 576, "s16": 576, "H16": 576, "h16": 576, "B16": 576, "b16": 576,
	"Q17": 592, "q17": 592, "D17": 592, "d17": 592, "S17": 592, "s17": 592, "H17": 592, "h17": 592, "B17": 592, "b17": 592,
	"Q18": 608, "q18": 608, "D18": 608, "d18": 608, "S18": 608, "s18": 608, "H18": 608, "h18": 608, "B18": 608, "b18": 608,
	"Q19": 624, "q19": 624, "D19": 624, "d19": 624, "S19": 624, "s19": 624, "H19": 624, "h19": 624, "B19": 624, "b19": 624,
	"Q20": 640, "q20": 640, "D20": 640, "d20": 640, "S20": 640, "s20": 640, "H20": 640, "h20": 640, "B20": 640, "b20": 640,
	"Q21": 656, "q21": 656, "D21": 656, "d21": 656, "S21": 656, "s21": 656, "H21": 656, "h21": 656, "B21": 656, "b21": 656,
	"Q22": 672, "q22": 672, "D22": 672, "d22": 672, "S22": 672, "s22": 672, "H22": 672, "h22": 672, "B22": 672, "b22": 672,
	"Q23": 688, "q23": 688, "D23": 688, "d23": 688, "S23": 688, "s23": 688, "H23": 688, "h23": 688, "B23": 688, "b23": 688,
	"Q24": 704, "q24": 704, "D24": 704, "d24": 704, "S24": 704, "s24": 704, "H24": 704, "h24": 704, "B24": 704, "b24": 704,
	"Q25": 720, "q25": 720, "D25": 720, "d25": 720, "S25": 720, "s25": 720, "H25": 720, "h25": 720, "B25": 720, "b25": 720,
	"Q26": 736, "q26": 736, "D26": 736, "d26": 736, "S26": 736, "s26": 736, "H26": 736, "h26": 736, "B26": 736, "b26": 736,
	"Q27": 752, "q27": 752, "D27": 752, "d27": 752, "S27": 752, "s27": 752, "H27": 752, "h27": 752, "B27": 752, "b27": 752,
	"Q28": 768, "q28": 768, "D28": 768, "d28": 768, "S28": 768, "s28": 768, "H28": 768, "h28": 768, "B28": 768, "b28": 768,
	"Q29": 784, "q29": 784, "D29": 784, "d29": 784, "S29": 784, "s29": 784, "H29": 784, "h29": 784, "B29": 784, "b29": 784,
	"Q30": 800, "q30": 800, "D30": 800, "d30": 800, "S30": 800, "s30": 800, "H30": 800, "h30": 800, "B30": 800, "b30": 800,
	"Q31": 816, "q31": 816, "D31": 816, "d31": 816, "S31": 816, "s31": 816, "H31": 816, "h31": 816, "B31": 816, "b31": 816,

	// FPSR QC标志
	"QC_FLAG": 832, "qc_flag": 832,

	// 其他系统寄存器
	"FPCR": 848, "fpcr": 848,
}

// GetARM64RegisterOffset 根据寄存器名称返回对应的偏移值
func GetARM64RegisterOffset(regName string) (int, bool) {
	offset, exists := ARM64RegisterOffsets[regName]
	return offset, exists
}

const (
	IjkInvalid      IRJumpKind = 0x1A00
	IjkBoring       IRJumpKind = 0x1A01 // 普通跳转，只是到下一个位置
	IjkCall         IRJumpKind = 0x1A02 // 函数调用
	IjkRet          IRJumpKind = 0x1A03 // 函数返回
	IjkClientReq    IRJumpKind = 0x1A04 // 执行客户端请求后再继续
	IjkYield        IRJumpKind = 0x1A05 // 客户端让出线程调度
	IjkEmWarn       IRJumpKind = 0x1A06 // 报告模拟警告后继续
	IjkEmFail       IRJumpKind = 0x1A07 // 模拟关键错误，放弃执行
	IjkNoDecode     IRJumpKind = 0x1A08 // 当前指令无法解码
	IjkMapFail      IRJumpKind = 0x1A09 // VEX提供的地址转换失败
	IjkInvalICache  IRJumpKind = 0x1A0A // 使区域[CMSTART, +CMLEN)的指令缓存无效
	IjkFlushDCache  IRJumpKind = 0x1A0B // 刷新区域[CMSTART, +CMLEN)的数据缓存
	IjkNoRedir      IRJumpKind = 0x1A0C // 跳转到未重定向的客户地址
	IjkSigILL       IRJumpKind = 0x1A0D // 当前指令产生SIGILL
	IjkSigTRAP      IRJumpKind = 0x1A0E // 当前指令产生SIGTRAP
	IjkSigSEGV      IRJumpKind = 0x1A0F // 当前指令产生SIGSEGV
	IjkSigBUS       IRJumpKind = 0x1A10 // 当前指令产生SIGBUS
	IjkSigFPE       IRJumpKind = 0x1A11 // 当前指令产生通用SIGFPE
	IjkSigFPEIntDiv IRJumpKind = 0x1A12 // 当前指令产生SIGFPE-IntDiv
	IjkSigFPEIntOvf IRJumpKind = 0x1A13 // 当前指令产生SIGFPE-IntOvf
	IjkPrivileged   IRJumpKind = 0x1A14 // 当前指令应根据权限级别失败
	// 系统调用相关跳转类型
	IjkSysSyscall  IRJumpKind = 0x1A15 // amd64/x86 'syscall', ppc 'sc', arm 'svc #0'
	IjkSysInt      IRJumpKind = 0x1A16 // amd64/x86 'int *'
	IjkSysInt32    IRJumpKind = 0x1A17 // amd64/x86 'int $0x20'
	IjkSysInt128   IRJumpKind = 0x1A18 // amd64/x86 'int $0x80'
	IjkSysInt129   IRJumpKind = 0x1A19 // amd64/x86 'int $0x81'
	IjkSysInt130   IRJumpKind = 0x1A1A // amd64/x86 'int $0x82'
	IjkSysInt145   IRJumpKind = 0x1A1B // amd64/x86 'int $0x91'
	IjkSysInt210   IRJumpKind = 0x1A1C // amd64/x86 'int $0xD2'
	IjkSysSysenter IRJumpKind = 0x1A1D // x86 'sysenter'
)

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

// NoOp 表示空操作
type NoOp struct {
	Dummy C.uint
}

// IMark 表示指令标记
type IMark struct {
	Addr  C.Addr  /* 指令地址 */
	Len   C.uint  /* 指令长度 */
	Delta C.uchar /* PC编码偏移 */
}

// AbiHint 表示 ABI 提示
type AbiHint struct {
	Base *IRExpr /* 未定义块的起始地址 */
	Len  C.int   /* 未定义块的长度 */
	Nia  *IRExpr /* 下一条指令的地址 */
}

// Put 表示写入固定偏移的寄存器
type Put struct {
	Offset C.int   /* 状态偏移量 */
	Data   *IRExpr /* 要写入的值 */
}

// PutI 表示写入非固定偏移的寄存器
type PutI struct {
	Details *C.IRPutI
}

// WrTmp 表示临时变量赋值
type WrTmp struct {
	Tmp  IRTemp  /* 临时变量（赋值左值）*/
	Data *IRExpr /* 表达式（赋值右值）*/
}

// Store 表示内存存储
type Store struct {
	End  C.IREndness /* 字节序 */
	Addr *IRExpr     /* 存储地址 */
	Data *IRExpr     /* 要写入的值 */
}

// StoreG 表示有条件的存储
type StoreG struct {
	Details *C.IRStoreG
}

// LoadG 表示有条件的加载
type LoadG struct {
	Details *C.IRLoadG
}

// CAS 表示原子比较和交换操作
type CAS struct {
	Details *C.IRCAS
}

// LLSC 表示 Load-Linked/Store-Conditional 操作
type LLSC struct {
	End       C.IREndness /* 字节序 */
	Result    IRTemp      /* 结果临时变量 */
	Addr      *IRExpr     /* 地址 */
	StoreData *IRExpr     /* NULL表示LL，非NULL表示SC */
}

// Dirty 表示调用有副作用的C函数
type Dirty struct {
	Details *C.IRDirty
}

// MBE 表示内存总线事件
type MBE struct {
	Event C.IRMBusEvent
}

// Exit 表示条件退出
type Exit struct {
	Guard  *IRExpr      /* 条件表达式 */
	Dst    *IRConst     /* 跳转目标（仅常量）*/
	Jk     C.IRJumpKind /* 跳转类型 */
	OffsIP C.int        /* IP的状态偏移 */
}

// Binder 表示 VEX 内部的模式匹配绑定器
type Binder struct {
	Binder C.int
}

// Get 表示从固定偏移读取寄存器
type Get struct {
	Offset C.int  /* 状态偏移量 */
	Ty     IRType /* 读取值的类型 */
}

// GetI 表示从非固定偏移读取寄存器（用于循环索引）
type GetI struct {
	Descr *C.IRRegArray /* 作为循环数组处理的状态部分 */
	Ix    *IRExpr       /* 数组索引的变量部分 */
	Bias  C.int         /* 数组索引的常量偏移部分 */
}

// RdTmp 表示读取临时变量
type RdTmp struct {
	Tmp IRTemp /* 临时变量编号 */
}

// Qop 表示四元操作
type Qop struct {
	Details *C.IRQop
}

// Triop 表示三元操作
type Triop struct {
	Details *C.IRTriop
}

// Binop 表示二元操作
type Binop struct {
	Op   IROp    /* 操作码 */
	Arg1 *IRExpr /* 操作数1 */
	Arg2 *IRExpr /* 操作数2 */
}

// Unop 表示一元操作
type Unop struct {
	Op  C.IROp  /* 操作码 */
	Arg *IRExpr /* 操作数 */
}

// Load 表示从内存加载（普通加载，非 Load-Linked）
type Load struct {
	End  C.IREndness /* 字节序 */
	Ty   C.IRType    /* 加载值的类型 */
	Addr *IRExpr     /* 加载地址 */
}

// Const 表示常量表达式
type Const struct {
	Con *IRConst /* 常量本身 */
}

// CCall 表示调用纯C函数（无副作用）
type CCall struct {
	Cee   *C.IRCallee /* 要调用的函数 */
	RetTy C.IRType    /* 返回值类型 */
	Args  **IRExpr    /* 参数表达式向量 */
}

// ITE 表示三元 if-then-else 操作（严格求值）
type ITE struct {
	Cond    *IRExpr /* 条件 */
	IfTrue  *IRExpr /* 真值表达式 */
	IfFalse *IRExpr /* 假值表达式 */
}

type IRStmt struct {
	Tag IRStmtTag
	Ist unsafe.Pointer
}

func (i *IRStmt) AsNoOp() *NoOp {
	if i.Tag != IstNoOp {
		panic("wrong type")
	}
	return (*NoOp)(unsafe.Pointer(&i.Ist))
}

func (i *IRStmt) AsIMark() *IMark {
	if i.Tag != IstIMark {
		panic("wrong type")
	}
	return (*IMark)(unsafe.Pointer(&i.Ist))
}

func (i *IRStmt) AsAbiHint() *AbiHint {
	if i.Tag != IstAbiHint {
		panic("wrong type")
	}
	return (*AbiHint)(unsafe.Pointer(&i.Ist))
}

func (i *IRStmt) AsPut() *Put {
	if i.Tag != IstPut {
		panic("wrong type")
	}
	return (*Put)(unsafe.Pointer(&i.Ist))
}

func (i *IRStmt) AsPutI() *PutI {
	if i.Tag != IstPutI {
		panic("wrong type")
	}
	return (*PutI)(unsafe.Pointer(&i.Ist))
}

func (i *IRStmt) AsWrTmp() *WrTmp {
	if i.Tag != IstWrTmp {
		panic("wrong type")
	}
	return (*WrTmp)(unsafe.Pointer(&i.Ist))
}

func (i *IRStmt) AsStore() *Store {
	if i.Tag != IstStore {
		panic("wrong type")
	}
	return (*Store)(unsafe.Pointer(&i.Ist))
}

func (i *IRStmt) AsStoreG() *StoreG {
	if i.Tag != IstStoreG {
		panic("wrong type")
	}
	return (*StoreG)(unsafe.Pointer(&i.Ist))
}

func (i *IRStmt) AsLoadG() *LoadG {
	if i.Tag != IstLoadG {
		panic("wrong type")
	}
	return (*LoadG)(unsafe.Pointer(&i.Ist))
}

func (i *IRStmt) AsCAS() *CAS {
	if i.Tag != IstCAS {
		panic("wrong type")
	}
	return (*CAS)(unsafe.Pointer(&i.Ist))
}

func (i *IRStmt) AsLLSC() *LLSC {
	if i.Tag != IstLLSC {
		panic("wrong type")
	}
	return (*LLSC)(unsafe.Pointer(&i.Ist))
}

func (i *IRStmt) AsDirty() *Dirty {
	if i.Tag != IstDirty {
		panic("wrong type")
	}
	return (*Dirty)(unsafe.Pointer(&i.Ist))
}

func (i *IRStmt) AsMBE() *MBE {
	if i.Tag != IstMBE {
		panic("wrong type")
	}
	return (*MBE)(unsafe.Pointer(&i.Ist))
}

func (i *IRStmt) AsExit() *Exit {
	if i.Tag != IstExit {
		panic("wrong type")
	}
	return (*Exit)(unsafe.Pointer(&i.Ist))
}

type IRExpr struct {
	Tag IRExprTag
	Iex unsafe.Pointer
}

func (i *IRExpr) AsBinder() *Binder {
	if i.Tag != IexBinder {
		panic("wrong type")
	}
	return (*Binder)(unsafe.Pointer(&i.Iex))
}

func (i *IRExpr) AsGet() *Get {
	if i.Tag != IexGet {
		panic("wrong type")
	}
	return (*Get)(unsafe.Pointer(&i.Iex))
}

func (i *IRExpr) AsGetI() *GetI {
	if i.Tag != IexGetI {
		panic("wrong type")
	}
	return (*GetI)(unsafe.Pointer(&i.Iex))
}

func (i *IRExpr) AsRdTmp() *RdTmp {
	if i.Tag != IexRdTmp {
		panic("wrong type")
	}
	return (*RdTmp)(unsafe.Pointer(&i.Iex))
}

func (i *IRExpr) AsQop() *Qop {
	if i.Tag != IexQop {
		panic("wrong type")
	}
	return (*Qop)(unsafe.Pointer(&i.Iex))
}

func (i *IRExpr) AsTriop() *Triop {
	if i.Tag != IexTriop {
		panic("wrong type")
	}
	return (*Triop)(unsafe.Pointer(&i.Iex))
}

func (i *IRExpr) AsBinop() *Binop {
	if i.Tag != IexBinop {
		panic("wrong type")
	}
	return (*Binop)(unsafe.Pointer(&i.Iex))
}

func (i *IRExpr) AsUnop() *Unop {
	if i.Tag != IexUnop {
		panic("wrong type")
	}
	return (*Unop)(unsafe.Pointer(&i.Iex))
}

func (i *IRExpr) AsLoad() *Load {
	if i.Tag != IexLoad {
		panic("wrong type")
	}
	return (*Load)(unsafe.Pointer(&i.Iex))
}

func (i *IRExpr) AsConst() *Const {
	if i.Tag != IexConst {
		panic("wrong type")
	}
	return (*Const)(unsafe.Pointer(&i.Iex))
}

func (i *IRExpr) AsCCall() *CCall {
	if i.Tag != IexCCall {
		panic("wrong type")
	}
	return (*CCall)(unsafe.Pointer(&i.Iex))
}

func (i *IRExpr) AsITE() *ITE {
	if i.Tag != IexITE {
		panic("wrong type")
	}
	return (*ITE)(unsafe.Pointer(&i.Iex))
}

type IRTypeEnv struct {
	Types     unsafe.Pointer // 指向IRType数组的指针
	TypesSize C.Int          // 数组的大小
	TypesUsed C.Int          // 实际使用的类型数量
}

// GetType 根据索引获取IRType
func (e *IRTypeEnv) GetType(idx int) IRType {
	if idx < 0 || idx >= int(e.TypesUsed) {
		// 索引超出范围
		return ItyINVALID
	}
	// 获取指定索引的IRType
	typesArray := (*[1 << 30]IRType)(e.Types)
	return typesArray[idx]
}

type IRSb struct {
	TyEnv     *IRTypeEnv
	Stmts     **C.IRStmt
	StmtsSize C.Int
	StmtsUsed C.Int
	Next      *IRExpr
	JumpKind  IRJumpKind
	OffsIP    C.Int
}

func (isb *IRSb) GetStmt(index int) *IRStmt {
	if index < 0 || index >= int(isb.StmtsUsed) {
		return nil
	}
	return (*IRStmt)(unsafe.Pointer(*(**C.IRStmt)(unsafe.Pointer(uintptr(unsafe.Pointer(isb.Stmts)) + uintptr(index)*unsafe.Sizeof(uintptr(0))))))
}
