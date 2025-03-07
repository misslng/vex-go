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

type IRJumpKind uint32

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

// ARM64 register offsets in VexGuestARM64State
const (
	// General purpose registers
	ARM64X0  = 16  // offset for X0
	ARM64X1  = 24  // X0 + 8
	ARM64X2  = 32  // X1 + 8
	ARM64X3  = 40  // X2 + 8
	ARM64X4  = 48  // X3 + 8
	ARM64X5  = 56  // X4 + 8
	ARM64X6  = 64  // X5 + 8
	ARM64X7  = 72  // X6 + 8
	ARM64X8  = 80  // X7 + 8
	ARM64X9  = 88  // X8 + 8
	ARM64X10 = 96  // X9 + 8
	ARM64X11 = 104 // X10 + 8
	ARM64X12 = 112 // X11 + 8
	ARM64X13 = 120 // X12 + 8
	ARM64X14 = 128 // X13 + 8
	ARM64X15 = 136 // X14 + 8
	ARM64X16 = 144 // X15 + 8
	ARM64X17 = 152 // X16 + 8
	ARM64X18 = 160 // X17 + 8
	ARM64X19 = 168 // X18 + 8
	ARM64X20 = 176 // X19 + 8
	ARM64X21 = 184 // X20 + 8
	ARM64X22 = 192 // X21 + 8
	ARM64X23 = 200 // X22 + 8
	ARM64X24 = 208 // X23 + 8
	ARM64X25 = 216 // X24 + 8
	ARM64X26 = 224 // X25 + 8
	ARM64X27 = 232 // X26 + 8
	ARM64X28 = 240 // X27 + 8
	ARM64X29 = 248 // X28 + 8 (Frame Pointer)
	ARM64X30 = 256 // X29 + 8 (Link Register)
	ARM64SP  = 264 // X30 + 8 (Stack Pointer)
	ARM64PC  = 272 // SP + 8 (Program Counter)

	// Condition flags related
	ARM64CCOp   = 280 // PC + 8
	ARM64CCDep1 = 288 // CC_OP + 8
	ARM64CCDep2 = 296 // CC_DEP1 + 8
	ARM64CCNDep = 304 // CC_DEP2 + 8

	// Thread register
	ARM64TpidrEl0 = 312 // CC_NDEP + 8

	// SIMD/FP registers (Q0-Q31, 128-bit each)
	ARM64Q0  = 320 // TPIDR_EL0 + 8
	ARM64Q1  = 336 // Q0 + 16
	ARM64Q2  = 352 // Q1 + 16
	ARM64Q3  = 368 // Q2 + 16
	ARM64Q4  = 384 // Q3 + 16
	ARM64Q5  = 400 // Q4 + 16
	ARM64Q6  = 416 // Q5 + 16
	ARM64Q7  = 432 // Q6 + 16
	ARM64Q8  = 448 // Q7 + 16
	ARM64Q9  = 464 // Q8 + 16
	ARM64Q10 = 480 // Q9 + 16
	ARM64Q11 = 496 // Q10 + 16
	ARM64Q12 = 512 // Q11 + 16
	ARM64Q13 = 528 // Q12 + 16
	ARM64Q14 = 544 // Q13 + 16
	ARM64Q15 = 560 // Q14 + 16
	ARM64Q16 = 576 // Q15 + 16
	ARM64Q17 = 592 // Q16 + 16
	ARM64Q18 = 608 // Q17 + 16
	ARM64Q19 = 624 // Q18 + 16
	ARM64Q20 = 640 // Q19 + 16
	ARM64Q21 = 656 // Q20 + 16
	ARM64Q22 = 672 // Q21 + 16
	ARM64Q23 = 688 // Q22 + 16
	ARM64Q24 = 704 // Q23 + 16
	ARM64Q25 = 720 // Q24 + 16
	ARM64Q26 = 736 // Q25 + 16
	ARM64Q27 = 752 // Q26 + 16
	ARM64Q28 = 768 // Q27 + 16
	ARM64Q29 = 784 // Q28 + 16
	ARM64Q30 = 800 // Q29 + 16
	ARM64Q31 = 816 // Q30 + 16

	// FPSR QC flag
	ARM64QCFlag = 832 // Q31 + 16

	// Other system registers
	ARM64FPCR = 848 // QCFLAG + 16
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
	Dst    *C.IRConst   /* 跳转目标（仅常量）*/
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
	Op   C.IROp  /* 操作码 */
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
	Con *C.IRConst /* 常量本身 */
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
