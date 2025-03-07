package vex_go

/*
#cgo CFLAGS: -I${SRCDIR}/vex/pub -I${SRCDIR}/pyvex_c
#cgo LDFLAGS: -L${SRCDIR} -lpyvex
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
	Ist_NoOp    IRStmtTag = 0x1E00 // 7680
	Ist_IMark   IRStmtTag = 0x1E01 // 7681
	Ist_AbiHint IRStmtTag = 0x1E02 // 7682
	Ist_Put     IRStmtTag = 0x1E03 // 7683
	Ist_PutI    IRStmtTag = 0x1E04 // 7684
	Ist_WrTmp   IRStmtTag = 0x1E05 // 7685
	Ist_Store   IRStmtTag = 0x1E06 // 7686
	Ist_LoadG   IRStmtTag = 0x1E07 // 7687
	Ist_StoreG  IRStmtTag = 0x1E08 // 7688
	Ist_CAS     IRStmtTag = 0x1E09 // 7689
	Ist_LLSC    IRStmtTag = 0x1E0A // 7690
	Ist_Dirty   IRStmtTag = 0x1E0B // 7691
	Ist_MBE     IRStmtTag = 0x1E0C // 7692
	Ist_Exit    IRStmtTag = 0x1E0D // 7693
)

// IRExprTag 表示 VEX IR 表达式的类型
type IRExprTag uint32

const (
	Iex_Binder IRExprTag = 0x1900 + iota // 用于 VEX 内部模式匹配的绑定器
	Iex_Get                              // 从固定偏移读取寄存器
	Iex_GetI                             // 从非固定偏移读取寄存器（数组访问）
	Iex_RdTmp                            // 读取临时变量
	Iex_Qop                              // 四元运算
	Iex_Triop                            // 三元运算
	Iex_Binop                            // 二元运算
	Iex_Unop                             // 一元运算
	Iex_Load                             // 内存加载
	Iex_Const                            // 常量
	Iex_ITE                              // if-then-else 表达式
	Iex_CCall                            // 调用 C 函数
	Iex_VECRET                           // 向量返回值
	Iex_GSPTR                            // 获取状态指针
)

type IRType uint32

const (
	Ity_INVALID IRType = 0x1100 + iota
	Ity_I1             // 1位整数
	Ity_I8             // 8位整数
	Ity_I16            // 16位整数
	Ity_I32            // 32位整数
	Ity_I64            // 64位整数
	Ity_I128           // 128位标量
	Ity_F16            // 16位浮点数
	Ity_F32            // IEEE 754 单精度浮点数
	Ity_F64            // IEEE 754 双精度浮点数
	Ity_D32            // 32位十进制浮点数
	Ity_D64            // 64位十进制浮点数
	Ity_D128           // 128位十进制浮点数
	Ity_F128           // 128位浮点数（具体实现由平台定义）
	Ity_V128           // 128位 SIMD
	Ity_V256           // 256位 SIMD
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
	dummy C.uint
}

// IMark 表示指令标记
type IMark struct {
	Addr  C.Addr  /* 指令地址 */
	Len   C.uint  /* 指令长度 */
	Delta C.uchar /* PC编码偏移 */
}

// AbiHint 表示 ABI 提示
type AbiHint struct {
	base *C.IRExpr /* 未定义块的起始地址 */
	len  C.int     /* 未定义块的长度 */
	nia  *C.IRExpr /* 下一条指令的地址 */
}

// Put 表示写入固定偏移的寄存器
type Put struct {
	offset C.int     /* 状态偏移量 */
	data   *C.IRExpr /* 要写入的值 */
}

// PutI 表示写入非固定偏移的寄存器
type PutI struct {
	details *C.IRPutI
}

// WrTmp 表示临时变量赋值
type WrTmp struct {
	Tmp  C.IRTemp /* 临时变量（赋值左值）*/
	Data *IRExpr  /* 表达式（赋值右值）*/
}

// Store 表示内存存储
type Store struct {
	end  C.IREndness /* 字节序 */
	addr *C.IRExpr   /* 存储地址 */
	data *C.IRExpr   /* 要写入的值 */
}

// StoreG 表示有条件的存储
type StoreG struct {
	details *C.IRStoreG
}

// LoadG 表示有条件的加载
type LoadG struct {
	details *C.IRLoadG
}

// CAS 表示原子比较和交换操作
type CAS struct {
	details *C.IRCAS
}

// LLSC 表示 Load-Linked/Store-Conditional 操作
type LLSC struct {
	end       C.IREndness /* 字节序 */
	result    C.IRTemp    /* 结果临时变量 */
	addr      *C.IRExpr   /* 地址 */
	storedata *C.IRExpr   /* NULL表示LL，非NULL表示SC */
}

// Dirty 表示调用有副作用的C函数
type Dirty struct {
	details *C.IRDirty
}

// MBE 表示内存总线事件
type MBE struct {
	event C.IRMBusEvent
}

// Exit 表示条件退出
type Exit struct {
	guard  *C.IRExpr    /* 条件表达式 */
	dst    *C.IRConst   /* 跳转目标（仅常量）*/
	jk     C.IRJumpKind /* 跳转类型 */
	offsIP C.int        /* IP的状态偏移 */
}

// Binder 表示 VEX 内部的模式匹配绑定器
type Binder struct {
	binder C.int
}

// Get 表示从固定偏移读取寄存器
type Get struct {
	Offset C.int  /* 状态偏移量 */
	Ty     IRType /* 读取值的类型 */
}

// GetI 表示从非固定偏移读取寄存器（用于循环索引）
type GetI struct {
	descr *C.IRRegArray /* 作为循环数组处理的状态部分 */
	ix    *C.IRExpr     /* 数组索引的变量部分 */
	bias  C.int         /* 数组索引的常量偏移部分 */
}

// RdTmp 表示读取临时变量
type RdTmp struct {
	tmp C.IRTemp /* 临时变量编号 */
}

// Qop 表示四元操作
type Qop struct {
	details *C.IRQop
}

// Triop 表示三元操作
type Triop struct {
	details *C.IRTriop
}

// Binop 表示二元操作
type Binop struct {
	op   C.IROp    /* 操作码 */
	arg1 *C.IRExpr /* 操作数1 */
	arg2 *C.IRExpr /* 操作数2 */
}

// Unop 表示一元操作
type Unop struct {
	op  C.IROp    /* 操作码 */
	arg *C.IRExpr /* 操作数 */
}

// Load 表示从内存加载（普通加载，非 Load-Linked）
type Load struct {
	end  C.IREndness /* 字节序 */
	ty   C.IRType    /* 加载值的类型 */
	addr *C.IRExpr   /* 加载地址 */
}

// Const 表示常量表达式
type Const struct {
	con *C.IRConst /* 常量本身 */
}

// CCall 表示调用纯C函数（无副作用）
type CCall struct {
	cee   *C.IRCallee /* 要调用的函数 */
	retty C.IRType    /* 返回值类型 */
	args  **C.IRExpr  /* 参数表达式向量 */
}

// ITE 表示三元 if-then-else 操作（严格求值）
type ITE struct {
	cond    *C.IRExpr /* 条件 */
	iftrue  *C.IRExpr /* 真值表达式 */
	iffalse *C.IRExpr /* 假值表达式 */
}

type IRStmt struct {
	tag IRStmtTag
	Ist unsafe.Pointer
}

func (i *IRStmt) AsNoOp() *NoOp {
	if i.tag != Ist_NoOp {
		panic("wrong type")
	}
	return (*NoOp)(unsafe.Pointer(&i.Ist))
}

func (i *IRStmt) AsIMark() *IMark {
	if i.tag != Ist_IMark {
		panic("wrong type")
	}
	return (*IMark)(unsafe.Pointer(&i.Ist))
}

func (i *IRStmt) AsAbiHint() *AbiHint {
	if i.tag != Ist_AbiHint {
		panic("wrong type")
	}
	return (*AbiHint)(unsafe.Pointer(&i.Ist))
}

func (i *IRStmt) AsPut() *Put {
	if i.tag != Ist_Put {
		panic("wrong type")
	}
	return (*Put)(unsafe.Pointer(&i.Ist))
}

func (i *IRStmt) AsPutI() *PutI {
	if i.tag != Ist_PutI {
		panic("wrong type")
	}
	return (*PutI)(unsafe.Pointer(&i.Ist))
}

func (i *IRStmt) AsWrTmp() *WrTmp {
	if i.tag != Ist_WrTmp {
		panic("wrong type")
	}
	return (*WrTmp)(unsafe.Pointer(&i.Ist))
}

func (i *IRStmt) AsStore() *Store {
	if i.tag != Ist_Store {
		panic("wrong type")
	}
	return (*Store)(unsafe.Pointer(&i.Ist))
}

func (i *IRStmt) AsStoreG() *StoreG {
	if i.tag != Ist_StoreG {
		panic("wrong type")
	}
	return (*StoreG)(unsafe.Pointer(&i.Ist))
}

func (i *IRStmt) AsLoadG() *LoadG {
	if i.tag != Ist_LoadG {
		panic("wrong type")
	}
	return (*LoadG)(unsafe.Pointer(&i.Ist))
}

func (i *IRStmt) AsCAS() *CAS {
	if i.tag != Ist_CAS {
		panic("wrong type")
	}
	return (*CAS)(unsafe.Pointer(&i.Ist))
}

func (i *IRStmt) AsLLSC() *LLSC {
	if i.tag != Ist_LLSC {
		panic("wrong type")
	}
	return (*LLSC)(unsafe.Pointer(&i.Ist))
}

func (i *IRStmt) AsDirty() *Dirty {
	if i.tag != Ist_Dirty {
		panic("wrong type")
	}
	return (*Dirty)(unsafe.Pointer(&i.Ist))
}

func (i *IRStmt) AsMBE() *MBE {
	if i.tag != Ist_MBE {
		panic("wrong type")
	}
	return (*MBE)(unsafe.Pointer(&i.Ist))
}

func (i *IRStmt) AsExit() *Exit {
	if i.tag != Ist_Exit {
		panic("wrong type")
	}
	return (*Exit)(unsafe.Pointer(&i.Ist))
}

type IRExpr struct {
	tag IRExprTag
	Iex unsafe.Pointer
}

func (i *IRExpr) AsBinder() *Binder {
	if i.tag != Iex_Binder {
		panic("wrong type")
	}
	return (*Binder)(unsafe.Pointer(&i.Iex))
}

func (i *IRExpr) AsGet() *Get {
	if i.tag != Iex_Get {
		panic("wrong type")
	}
	return (*Get)(unsafe.Pointer(&i.Iex))
}

func (i *IRExpr) AsGetI() *GetI {
	if i.tag != Iex_GetI {
		panic("wrong type")
	}
	return (*GetI)(unsafe.Pointer(&i.Iex))
}

func (i *IRExpr) AsRdTmp() *RdTmp {
	if i.tag != Iex_RdTmp {
		panic("wrong type")
	}
	return (*RdTmp)(unsafe.Pointer(&i.Iex))
}

func (i *IRExpr) AsQop() *Qop {
	if i.tag != Iex_Qop {
		panic("wrong type")
	}
	return (*Qop)(unsafe.Pointer(&i.Iex))
}

func (i *IRExpr) AsTriop() *Triop {
	if i.tag != Iex_Triop {
		panic("wrong type")
	}
	return (*Triop)(unsafe.Pointer(&i.Iex))
}

func (i *IRExpr) AsBinop() *Binop {
	if i.tag != Iex_Binop {
		panic("wrong type")
	}
	return (*Binop)(unsafe.Pointer(&i.Iex))
}

func (i *IRExpr) AsUnop() *Unop {
	if i.tag != Iex_Unop {
		panic("wrong type")
	}
	return (*Unop)(unsafe.Pointer(&i.Iex))
}

func (i *IRExpr) AsLoad() *Load {
	if i.tag != Iex_Load {
		panic("wrong type")
	}
	return (*Load)(unsafe.Pointer(&i.Iex))
}

func (i *IRExpr) AsConst() *Const {
	if i.tag != Iex_Const {
		panic("wrong type")
	}
	return (*Const)(unsafe.Pointer(&i.Iex))
}

func (i *IRExpr) AsCCall() *CCall {
	if i.tag != Iex_CCall {
		panic("wrong type")
	}
	return (*CCall)(unsafe.Pointer(&i.Iex))
}

func (i *IRExpr) AsITE() *ITE {
	if i.tag != Iex_ITE {
		panic("wrong type")
	}
	return (*ITE)(unsafe.Pointer(&i.Iex))
}

type IRSb struct {
	tyEnv     *C.IRTypeEnv
	stmts     **C.IRStmt
	StmtsSize C.Int
	StmtsUsed C.Int
	next      *C.IRExpr
	jumpKind  C.IRJumpKind
	OffsIP    C.Int
}

func (isb *IRSb) GetStmt(index int) *IRStmt {
	if index < 0 || index >= int(isb.StmtsUsed) {
		return nil
	}
	return (*IRStmt)(unsafe.Pointer(*(**C.IRStmt)(unsafe.Pointer(uintptr(unsafe.Pointer(isb.stmts)) + uintptr(index)*unsafe.Sizeof(uintptr(0))))))
}
