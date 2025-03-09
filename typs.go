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
	"fmt"
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
	IcoU1 IRConstTag = 0x1300 + iota
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

	// CAS比较操作
	IopCasCmpEQ8  IROp = 0x1400 + 49
	IopCasCmpEQ16 IROp = 0x1400 + 50
	IopCasCmpEQ32 IROp = 0x1400 + 51
	IopCasCmpEQ64 IROp = 0x1400 + 52
	IopCasCmpNE8  IROp = 0x1400 + 53
	IopCasCmpNE16 IROp = 0x1400 + 54
	IopCasCmpNE32 IROp = 0x1400 + 55
	IopCasCmpNE64 IROp = 0x1400 + 56

	// 需要昂贵的确定性跟踪的比较操作
	IopExpCmpNE8  IROp = 0x1400 + 57
	IopExpCmpNE16 IROp = 0x1400 + 58
	IopExpCmpNE32 IROp = 0x1400 + 59
	IopExpCmpNE64 IROp = 0x1400 + 60

	// 扩展乘法（有符号和无符号）
	IopMullS8  IROp = 0x1400 + 61
	IopMullS16 IROp = 0x1400 + 62
	IopMullS32 IROp = 0x1400 + 63
	IopMullS64 IROp = 0x1400 + 64
	IopMullU8  IROp = 0x1400 + 65
	IopMullU16 IROp = 0x1400 + 66
	IopMullU32 IROp = 0x1400 + 67
	IopMullU64 IROp = 0x1400 + 68

	// 整数特殊操作
	IopClz64 IROp = 0x1400 + 69 // 计算前导零数
	IopClz32 IROp = 0x1400 + 70
	IopCtz64 IROp = 0x1400 + 71 // 计算尾随零数
	IopCtz32 IROp = 0x1400 + 72

	// 标准整数比较（有符号和无符号）
	IopCmpLT32S IROp = 0x1400 + 73
	IopCmpLT64S IROp = 0x1400 + 74
	IopCmpLE32S IROp = 0x1400 + 75
	IopCmpLE64S IROp = 0x1400 + 76
	IopCmpLT32U IROp = 0x1400 + 77
	IopCmpLT64U IROp = 0x1400 + 78
	IopCmpLE32U IROp = 0x1400 + 79
	IopCmpLE64U IROp = 0x1400 + 80

	// Valgrind-Memcheck相关操作
	IopCmpNEZ8   IROp = 0x1400 + 81
	IopCmpNEZ16  IROp = 0x1400 + 82
	IopCmpNEZ32  IROp = 0x1400 + 83
	IopCmpNEZ64  IROp = 0x1400 + 84
	IopCmpwNEZ32 IROp = 0x1400 + 85 // 全0 -> 全0; 其他 -> 全1
	IopCmpwNEZ64 IROp = 0x1400 + 86
	IopLeft8     IROp = 0x1400 + 87 // \x -> x | -x
	IopLeft16    IROp = 0x1400 + 88
	IopLeft32    IROp = 0x1400 + 89
	IopLeft64    IROp = 0x1400 + 90
	IopMax32U    IROp = 0x1400 + 91 // 无符号最大值

	// PowerPC风格三路整数比较
	// op(x,y) | x < y = 0x8, x > y = 0x4, x == y = 0x2
	IopCmpORD32U IROp = 0x1400 + 92
	IopCmpORD64U IROp = 0x1400 + 93
	IopCmpORD32S IROp = 0x1400 + 94
	IopCmpORD64S IROp = 0x1400 + 95

	// 除法操作
	IopDivU32  IROp = 0x1400 + 96  // I32,I32 -> I32 (简单除法，无模)
	IopDivS32  IROp = 0x1400 + 97  // 同上，有符号
	IopDivU64  IROp = 0x1400 + 98  // I64,I64 -> I64
	IopDivS64  IROp = 0x1400 + 99  // 同上，有符号
	IopDivU64E IROp = 0x1400 + 100 // 被除数是64位参数(高)与64个0(低)连接
	IopDivS64E IROp = 0x1400 + 101 // 同上，有符号
	IopDivU32E IROp = 0x1400 + 102 // 被除数是32位参数(高)与32个0(低)连接
	IopDivS32E IROp = 0x1400 + 103 // 同上，有符号

	// DivMod操作 - 同时返回除法和取模结果
	IopDivModU64to32  IROp = 0x1400 + 104 // I64,I32 -> I64，其中低半是商，高半是余数
	IopDivModS64to32  IROp = 0x1400 + 105 // 同上，有符号
	IopDivModU128to64 IROp = 0x1400 + 106 // V128,I64 -> V128，其中低半是商，高半是余数
	IopDivModS128to64 IROp = 0x1400 + 107 // 同上，有符号
	IopDivModS64to64  IROp = 0x1400 + 108 // I64,I64 -> I128，其中低半是商，高半是余数

	// 整数扩展转换（无符号）
	Iop8Uto16  IROp = 0x1400 + 109
	Iop8Uto32  IROp = 0x1400 + 110
	Iop8Uto64  IROp = 0x1400 + 111
	Iop16Uto32 IROp = 0x1400 + 112
	Iop16Uto64 IROp = 0x1400 + 113
	Iop32Uto64 IROp = 0x1400 + 114

	// 整数扩展转换（有符号）
	Iop8Sto16  IROp = 0x1400 + 115
	Iop8Sto32  IROp = 0x1400 + 116
	Iop8Sto64  IROp = 0x1400 + 117
	Iop16Sto32 IROp = 0x1400 + 118
	Iop16Sto64 IROp = 0x1400 + 119
	Iop32Sto64 IROp = 0x1400 + 120

	// 整数缩小转换
	Iop64to8  IROp = 0x1400 + 121
	Iop32to8  IROp = 0x1400 + 122
	Iop64to16 IROp = 0x1400 + 123

	// 8 <-> 16 位转换
	Iop16to8   IROp = 0x1400 + 124 // I16 -> I8, 低半部分
	Iop16HIto8 IROp = 0x1400 + 125 // I16 -> I8, 高半部分
	Iop8HLto16 IROp = 0x1400 + 126 // (I8,I8) -> I16

	// 16 <-> 32 位转换
	Iop32to16   IROp = 0x1400 + 127 // I32 -> I16, 低半部分
	Iop32HIto16 IROp = 0x1400 + 128 // I32 -> I16, 高半部分
	Iop16HLto32 IROp = 0x1400 + 129 // (I16,I16) -> I32

	// 32 <-> 64 位转换
	Iop64to32   IROp = 0x1400 + 130 // I64 -> I32, 低半部分
	Iop64HIto32 IROp = 0x1400 + 131 // I64 -> I32, 高半部分
	Iop32HLto64 IROp = 0x1400 + 132 // (I32,I32) -> I64

	// 64 <-> 128 位转换
	Iop128to64   IROp = 0x1400 + 133 // I128 -> I64, 低半部分
	Iop128HIto64 IROp = 0x1400 + 134 // I128 -> I64, 高半部分
	Iop64HLto128 IROp = 0x1400 + 135 // (I64,I64) -> I128

	// 1位操作
	IopNot1   IROp = 0x1400 + 136 // Ity_Bit -> Ity_Bit
	Iop32to1  IROp = 0x1400 + 137 // Ity_I32 -> Ity_Bit, 仅选择bit[0]
	Iop64to1  IROp = 0x1400 + 138 // Ity_I64 -> Ity_Bit, 仅选择bit[0]
	Iop1Uto8  IROp = 0x1400 + 139 // Ity_Bit -> Ity_I8, 无符号扩展
	Iop1Uto32 IROp = 0x1400 + 140 // Ity_Bit -> Ity_I32, 无符号扩展
	Iop1Uto64 IROp = 0x1400 + 141 // Ity_Bit -> Ity_I64, 无符号扩展
	Iop1Sto8  IROp = 0x1400 + 142 // Ity_Bit -> Ity_I8, 有符号扩展
	Iop1Sto16 IROp = 0x1400 + 143 // Ity_Bit -> Ity_I16, 有符号扩展
	Iop1Sto32 IROp = 0x1400 + 144 // Ity_Bit -> Ity_I32, 有符号扩展
	Iop1Sto64 IROp = 0x1400 + 145 // Ity_Bit -> Ity_I64, 有符号扩展

	// 浮点操作 - 尝试符合IEEE754标准
	// 二进制操作，带舍入
	// IRRoundingMode(I32) x F64 x F64 -> F64
	IopAddF64 IROp = 0x1400 + 146
	IopSubF64 IROp = 0x1400 + 147
	IopMulF64 IROp = 0x1400 + 148
	IopDivF64 IROp = 0x1400 + 149

	// IRRoundingMode(I32) x F32 x F32 -> F32
	IopAddF32 IROp = 0x1400 + 150
	IopSubF32 IROp = 0x1400 + 151
	IopMulF32 IROp = 0x1400 + 152
	IopDivF32 IROp = 0x1400 + 153

	// 结果先舍入到IEEE浮点范围的变体
	IopAddF64r32 IROp = 0x1400 + 154
	IopSubF64r32 IROp = 0x1400 + 155
	IopMulF64r32 IROp = 0x1400 + 156
	IopDivF64r32 IROp = 0x1400 + 157

	// 一元操作，不带舍入
	IopNegF64 IROp = 0x1400 + 158 // F64 -> F64
	IopAbsF64 IROp = 0x1400 + 159 // F64 -> F64

	IopNegF32 IROp = 0x1400 + 160 // F32 -> F32
	IopAbsF32 IROp = 0x1400 + 161 // F32 -> F32

	// 浮点操作 - 开方、比较
	IopSqrtF64 IROp = 0x1400 + 162 // IRRoundingMode(I32) x F64 -> F64
	IopSqrtF32 IROp = 0x1400 + 163 // IRRoundingMode(I32) x F32 -> F32
	IopCmpF64  IROp = 0x1400 + 164 // F64 x F64 -> IRCmpF64Result(I32)
	IopCmpF32  IROp = 0x1400 + 165 // F32 x F32 -> IRCmpF32Result(I32)
	IopCmpF128 IROp = 0x1400 + 166 // F128 x F128 -> IRCmpF128Result(I32)

	// 浮点数与整数转换
	IopF64toI16S IROp = 0x1400 + 167 // IRRoundingMode(I32) x F64 -> signed I16
	IopF64toI32S IROp = 0x1400 + 168 // IRRoundingMode(I32) x F64 -> signed I32
	IopF64toI64S IROp = 0x1400 + 169 // IRRoundingMode(I32) x F64 -> signed I64
	IopF64toI64U IROp = 0x1400 + 170 // IRRoundingMode(I32) x F64 -> unsigned I64
	IopF64toI32U IROp = 0x1400 + 171 // IRRoundingMode(I32) x F64 -> unsigned I32

	IopI32StoF64 IROp = 0x1400 + 172 // signed I32 -> F64
	IopI64StoF64 IROp = 0x1400 + 173 // IRRoundingMode(I32) x signed I64 -> F64
	IopI64UtoF64 IROp = 0x1400 + 174 // IRRoundingMode(I32) x unsigned I64 -> F64
	IopI64UtoF32 IROp = 0x1400 + 175 // IRRoundingMode(I32) x unsigned I64 -> F32
	IopI32UtoF32 IROp = 0x1400 + 176 // IRRoundingMode(I32) x unsigned I32 -> F32
	IopI32UtoF64 IROp = 0x1400 + 177 // unsigned I32 -> F64

	IopF32toI32S IROp = 0x1400 + 178 // IRRoundingMode(I32) x F32 -> signed I32
	IopF32toI64S IROp = 0x1400 + 179 // IRRoundingMode(I32) x F32 -> signed I64
	IopF32toI32U IROp = 0x1400 + 180 // IRRoundingMode(I32) x F32 -> unsigned I32
	IopF32toI64U IROp = 0x1400 + 181 // IRRoundingMode(I32) x F32 -> unsigned I64

	// 有符号整数到浮点数的转换
	IopI32StoF32 IROp = 0x1400 + 182 // IRRoundingMode(I32) x signed I32 -> F32
	IopI64StoF32 IROp = 0x1400 + 183 // IRRoundingMode(I32) x signed I64 -> F32

	// 浮点格式之间的转换
	IopF32toF64 IROp = 0x1400 + 184 // F32 -> F64
	IopF64toF32 IROp = 0x1400 + 185 // IRRoundingMode(I32) x F64 -> F32

	// 重新解释：将F64转为I64（保持相同的位模式），或反向操作
	IopReinterpF64asI64 IROp = 0x1400 + 186 // F64 -> I64，保持位模式
	IopReinterpI64asF64 IROp = 0x1400 + 187 // I64 -> F64，保持位模式
	IopReinterpF32asI32 IROp = 0x1400 + 188 // F32 -> I32，保持位模式
	IopReinterpI32asF32 IROp = 0x1400 + 189 // I32 -> F32，保持位模式

	// 支持128位浮点数
	IopF64HLtoF128 IROp = 0x1400 + 190 // (F128的高半部分,F128的低半部分) -> F128
	IopF128HItoF64 IROp = 0x1400 + 191 // F128 -> F128的高半部分到F64寄存器
	IopF128LOtoF64 IROp = 0x1400 + 192 // F128 -> F128的低半部分到F64寄存器

	// 128位浮点算术运算
	// :: IRRoundingMode(I32) x F128 x F128 -> F128
	IopAddF128     IROp = 0x1400 + 193 // 加法
	IopSubF128     IROp = 0x1400 + 194 // 减法
	IopMulF128     IROp = 0x1400 + 195 // 乘法
	IopDivF128     IROp = 0x1400 + 196 // 除法
	IopMAddF128    IROp = 0x1400 + 197 // (A * B) + C
	IopMSubF128    IROp = 0x1400 + 198 // (A * B) - C
	IopNegMAddF128 IROp = 0x1400 + 199 // -((A * B) + C)
	IopNegMSubF128 IROp = 0x1400 + 200 // -((A * B) - C)
	IopNegF128     IROp = 0x1400 + 201 // 取负
	IopAbsF128     IROp = 0x1400 + 202 // 绝对值

	// :: IRRoundingMode(I32) x F128 -> F128
	IopSqrtF128 IROp = 0x1400 + 203 // 平方根

	// 整数到F128的转换
	IopI32StoF128 IROp = 0x1400 + 204 // signed I32 -> F128
	IopI64StoF128 IROp = 0x1400 + 205 // signed I64 -> F128
	IopI32UtoF128 IROp = 0x1400 + 206 // unsigned I32 -> F128
	IopI64UtoF128 IROp = 0x1400 + 207 // unsigned I64 -> F128
	IopF32toF128  IROp = 0x1400 + 208 // F32 -> F128
	IopF64toF128  IROp = 0x1400 + 209 // F64 -> F128

	// F128到整数的转换
	IopF128toI32S  IROp = 0x1400 + 210 // IRRoundingMode(I32) x F128 -> signed I32
	IopF128toI64S  IROp = 0x1400 + 211 // IRRoundingMode(I32) x F128 -> signed I64
	IopF128toI32U  IROp = 0x1400 + 212 // IRRoundingMode(I32) x F128 -> unsigned I32
	IopF128toI64U  IROp = 0x1400 + 213 // IRRoundingMode(I32) x F128 -> unsigned I64
	IopF128toI128S IROp = 0x1400 + 214 // IRRoundingMode(I32) x F128 -> signed I128
	IopF128toF64   IROp = 0x1400 + 215 // IRRoundingMode(I32) x F128 -> F64
	IopF128toF32   IROp = 0x1400 + 216 // IRRoundingMode(I32) x F128 -> F32
	IopRndF128     IROp = 0x1400 + 217 // IRRoundingMode(I32) x F128 -> F128

	// 截断到指定值，源和结果存储在F128寄存器中
	IopTruncF128toI32S IROp = 0x1400 + 218 // truncate F128 -> I32
	IopTruncF128toI32U IROp = 0x1400 + 219 // truncate F128 -> I32
	IopTruncF128toI64U IROp = 0x1400 + 220 // truncate F128 -> I64
	IopTruncF128toI64S IROp = 0x1400 + 221 // truncate F128 -> I64

	// --- x86/amd64特定操作，非754标准要求 ---
	// :: IRRoundingMode(I32) x F64 x F64 -> F64
	IopAtanF64       IROp = 0x1400 + 222 // FPATAN, arctan(arg1/arg2)
	IopYl2xF64       IROp = 0x1400 + 223 // FYL2X, arg1 * log2(arg2)
	IopYl2xp1F64     IROp = 0x1400 + 224 // FYL2XP1, arg1 * log2(arg2+1.0)
	IopPRemF64       IROp = 0x1400 + 225 // FPREM, 非IEEE余数(arg1/arg2)
	IopPRemC3210F64  IROp = 0x1400 + 226 // FPREM结果的C3210标志位, :: I32
	IopPRem1F64      IROp = 0x1400 + 227 // FPREM1, IEEE余数(arg1/arg2)
	IopPRem1C3210F64 IROp = 0x1400 + 228 // FPREM1结果的C3210标志位, :: I32
	IopScaleF64      IROp = 0x1400 + 229 // FSCALE, arg1 * (2^RoundTowardsZero(arg2))

	// :: IRRoundingMode(I32) x F64 -> F64
	IopSinF64         IROp = 0x1400 + 230 // FSIN
	IopCosF64         IROp = 0x1400 + 231 // FCOS
	IopTanF64         IROp = 0x1400 + 232 // FTAN
	Iop2xm1F64        IROp = 0x1400 + 233 // (2^arg - 1.0)
	IopRoundF128toInt IROp = 0x1400 + 234 // F128值舍入到最接近的整数值(仍为F128)
	IopRoundF64toInt  IROp = 0x1400 + 235 // F64值舍入到最接近的整数值(仍为F64)
	IopRoundF32toInt  IROp = 0x1400 + 236 // F32值舍入到最接近的整数值(仍为F32)

	// --- guest s390特定操作，非754标准要求 ---
	IopMAddF32 IROp = 0x1400 + 237 // (A * B) + C
	IopMSubF32 IROp = 0x1400 + 238 // (A * B) - C

	// --- guest ppc32/64特定操作，非754标准要求 ---
	IopMAddF64 IROp = 0x1400 + 239 // (A * B) + C
	IopMSubF64 IROp = 0x1400 + 240 // (A * B) - C

	IopMAddF64r32 IROp = 0x1400 + 241 // (A * B) + C，结果先舍入到F32范围
	IopMSubF64r32 IROp = 0x1400 + 242 // (A * B) - C，结果先舍入到F32范围

	IopRSqrtEst5GoodF64      IROp = 0x1400 + 243 // 倒数平方根估计，5个有效位
	IopRoundF64toF64_NEAREST IROp = 0x1400 + 244 // frin，舍入到最近
	IopRoundF64toF64_NegINF  IROp = 0x1400 + 245 // frim，舍入到负无穷
	IopRoundF64toF64_PosINF  IROp = 0x1400 + 246 // frip，舍入到正无穷
	IopRoundF64toF64_ZERO    IROp = 0x1400 + 247 // friz，舍入到零

	IopTruncF64asF32 IROp = 0x1400 + 248 // 按'fsts'执行F64->F32截断

	IopRoundF64toF32 IROp = 0x1400 + 249 // 将F64舍入到最接近的F32值(仍为F64)

	// --- guest arm64特定操作，非754标准要求 ---
	IopRecpExpF64 IROp = 0x1400 + 250 // FRECPX d :: IRRoundingMode(I32) x F64 -> F64
	IopRecpExpF32 IROp = 0x1400 + 251 // FRECPX s :: IRRoundingMode(I32) x F32 -> F32

	// --------- 可能由IEEE 754-2008要求 ---------
	IopMaxNumF64 IROp = 0x1400 + 252 // max, F64, 如果另一个是qNaN则返回数值操作数
	IopMinNumF64 IROp = 0x1400 + 253 // min, F64, 同上
	IopMaxNumF32 IROp = 0x1400 + 254 // max, F32, 同上
	IopMinNumF32 IROp = 0x1400 + 255 // min, F32, 同上

	// ------------------ 16位标量FP ------------------
	IopF16toF64 IROp = 0x1400 + 256 // F16 -> F64
	IopF64toF16 IROp = 0x1400 + 257 // IRRoundingMode(I32) x F64 -> F16

	IopF16toF32 IROp = 0x1400 + 258 // F16 -> F32
	IopF32toF16 IROp = 0x1400 + 259 // IRRoundingMode(I32) x F32 -> F16

	// ------------------ 32位SIMD整数 ------------------
	IopQAdd32S IROp = 0x1400 + 260
	IopQSub32S IROp = 0x1400 + 261

	IopAdd16x2   IROp = 0x1400 + 262
	IopSub16x2   IROp = 0x1400 + 263
	IopQAdd16Sx2 IROp = 0x1400 + 264
	IopQAdd16Ux2 IROp = 0x1400 + 265
	IopQSub16Sx2 IROp = 0x1400 + 266
	IopQSub16Ux2 IROp = 0x1400 + 267

	IopHAdd16Ux2 IROp = 0x1400 + 268
	IopHAdd16Sx2 IROp = 0x1400 + 269
	IopHSub16Ux2 IROp = 0x1400 + 270
	IopHSub16Sx2 IROp = 0x1400 + 271

	IopAdd8x4   IROp = 0x1400 + 272
	IopSub8x4   IROp = 0x1400 + 273
	IopQAdd8Sx4 IROp = 0x1400 + 274
	IopQAdd8Ux4 IROp = 0x1400 + 275
	IopQSub8Sx4 IROp = 0x1400 + 276
	IopQSub8Ux4 IROp = 0x1400 + 277

	// 8x4有符号/无符号半加/减。对每个通道，计算
	// sx(argL) + sx(argR)的位8:1，
	// 或zx(argL) - zx(argR)等
	IopHAdd8Ux4 IROp = 0x1400 + 278
	IopHAdd8Sx4 IROp = 0x1400 + 279
	IopHSub8Ux4 IROp = 0x1400 + 280
	IopHSub8Sx4 IROp = 0x1400 + 281

	// 8x4无符号绝对差的和
	IopSad8Ux4 IROp = 0x1400 + 282

	// 其他(向量整数比较 != 0)
	IopCmpNEZ16x2 IROp = 0x1400 + 283
	IopCmpNEZ8x4  IROp = 0x1400 + 284

	// ------------------ 64位SIMD浮点 --------------------

	// 转换到/从整数
	IopI32UtoFx2    IROp = 0x1400 + 285 // I32x4 -> F32x4
	IopI32StoFx2    IROp = 0x1400 + 286 // I32x4 -> F32x4
	IopFtoI32Ux2_RZ IROp = 0x1400 + 287 // F32x4 -> I32x4
	IopFtoI32Sx2_RZ IROp = 0x1400 + 288 // F32x4 -> I32x4

	// Fixed32格式是具有固定小数位数的浮点数。
	// 小数位数作为I8类型的第二个参数传递。
	IopF32ToFixed32Ux2_RZ IROp = 0x1400 + 289 // fp -> 定点
	IopF32ToFixed32Sx2_RZ IROp = 0x1400 + 290 // fp -> 定点
	IopFixed32UToF32x2_RN IROp = 0x1400 + 291 // 定点 -> fp
	IopFixed32SToF32x2_RN IROp = 0x1400 + 292 // 定点 -> fp

	// 二元操作
	IopMax32Fx2 IROp = 0x1400 + 293
	IopMin32Fx2 IROp = 0x1400 + 294

	// 成对最小和最大值
	IopPwMax32Fx2 IROp = 0x1400 + 295
	IopPwMin32Fx2 IROp = 0x1400 + 296

	// 注意：对于以下比较，arm前端假设参数中任一通道的nan返回该通道的零。
	IopCmpEQ32Fx2 IROp = 0x1400 + 297
	IopCmpGT32Fx2 IROp = 0x1400 + 298
	IopCmpGE32Fx2 IROp = 0x1400 + 299

	// 向量倒数估计在操作数向量的每个元素中找到近似倒数，
	// 并将结果放在目标向量中。
	IopRecipEst32Fx2 IROp = 0x1400 + 300

	// 向量倒数步骤计算(2.0 - arg1 * arg2)。
	// 注意，如果一个参数为零，另一个为任意符号的无穷大，操作结果为2.0。
	IopRecipStep32Fx2 IROp = 0x1400 + 301

	// 向量倒数平方根估计在操作数向量的每个元素中找到近似倒数平方根。
	IopRSqrtEst32Fx2 IROp = 0x1400 + 302

	// 向量倒数平方根步骤计算(3.0 - arg1 * arg2) / 2.0。
	// 注意，如果一个参数为零，另一个为任意符号的无穷大，操作结果为1.5。
	IopRSqrtStep32Fx2 IROp = 0x1400 + 303

	// 一元操作
	IopNeg32Fx2 IROp = 0x1400 + 304
	IopAbs32Fx2 IROp = 0x1400 + 305

	// ------------------ 64位SIMD整数 --------------------

	// 其他(向量整数比较 != 0)
	IopCmpNEZ8x8  IROp = 0x1400 + 306
	IopCmpNEZ16x4 IROp = 0x1400 + 307
	IopCmpNEZ32x2 IROp = 0x1400 + 308

	// 加法(普通/无符号饱和/有符号饱和)
	IopAdd8x8    IROp = 0x1400 + 309
	IopAdd16x4   IROp = 0x1400 + 310
	IopAdd32x2   IROp = 0x1400 + 311
	IopQAdd8Ux8  IROp = 0x1400 + 312
	IopQAdd16Ux4 IROp = 0x1400 + 313
	IopQAdd32Ux2 IROp = 0x1400 + 314
	IopQAdd64Ux1 IROp = 0x1400 + 315
	IopQAdd8Sx8  IROp = 0x1400 + 316
	IopQAdd16Sx4 IROp = 0x1400 + 317
	IopQAdd32Sx2 IROp = 0x1400 + 318
	IopQAdd64Sx1 IROp = 0x1400 + 319

	// 成对操作 - 对向量内每对相邻元素执行操作
	IopPwAdd8x8  IROp = 0x1400 + 320 // 成对加法8x8
	IopPwAdd16x4 IROp = 0x1400 + 321 // 成对加法16x4
	IopPwAdd32x2 IROp = 0x1400 + 322 // 成对加法32x2

	// 有符号/无符号成对最大值
	IopPwMax8Sx8  IROp = 0x1400 + 323 // 成对有符号最大值8x8
	IopPwMax16Sx4 IROp = 0x1400 + 324 // 成对有符号最大值16x4
	IopPwMax32Sx2 IROp = 0x1400 + 325 // 成对有符号最大值32x2
	IopPwMax8Ux8  IROp = 0x1400 + 326 // 成对无符号最大值8x8
	IopPwMax16Ux4 IROp = 0x1400 + 327 // 成对无符号最大值16x4
	IopPwMax32Ux2 IROp = 0x1400 + 328 // 成对无符号最大值32x2

	// 有符号/无符号成对最小值
	IopPwMin8Sx8  IROp = 0x1400 + 329 // 成对有符号最小值8x8
	IopPwMin16Sx4 IROp = 0x1400 + 330 // 成对有符号最小值16x4
	IopPwMin32Sx2 IROp = 0x1400 + 331 // 成对有符号最小值32x2
	IopPwMin8Ux8  IROp = 0x1400 + 332 // 成对无符号最小值8x8
	IopPwMin16Ux4 IROp = 0x1400 + 333 // 成对无符号最小值16x4
	IopPwMin32Ux2 IROp = 0x1400 + 334 // 成对无符号最小值32x2

	// 长度扩展变体是一元的。结果向量包含比操作数少两倍的元素，但它们宽两倍。
	// 例如:
	//    IopPwAddL16Ux4([a,b,c,d]) = [a+b,c+d]
	//    其中a+b和c+d是无符号32位值。
	IopPwAddL8Ux8  IROp = 0x1400 + 335 // 成对加法无符号长度扩展8x8
	IopPwAddL16Ux4 IROp = 0x1400 + 336 // 成对加法无符号长度扩展16x4
	IopPwAddL32Ux2 IROp = 0x1400 + 337 // 成对加法无符号长度扩展32x2
	IopPwAddL8Sx8  IROp = 0x1400 + 338 // 成对加法有符号长度扩展8x8
	IopPwAddL16Sx4 IROp = 0x1400 + 339 // 成对加法有符号长度扩展16x4
	IopPwAddL32Sx2 IROp = 0x1400 + 340 // 成对加法有符号长度扩展32x2

	// 减法(普通/无符号饱和/有符号饱和)
	IopSub8x8    IROp = 0x1400 + 341 // 减法8x8
	IopSub16x4   IROp = 0x1400 + 342 // 减法16x4
	IopSub32x2   IROp = 0x1400 + 343 // 减法32x2
	IopQSub8Ux8  IROp = 0x1400 + 344 // 无符号饱和减法8x8
	IopQSub16Ux4 IROp = 0x1400 + 345 // 无符号饱和减法16x4
	IopQSub32Ux2 IROp = 0x1400 + 346 // 无符号饱和减法32x2
	IopQSub64Ux1 IROp = 0x1400 + 347 // 无符号饱和减法64x1
	IopQSub8Sx8  IROp = 0x1400 + 348 // 有符号饱和减法8x8
	IopQSub16Sx4 IROp = 0x1400 + 349 // 有符号饱和减法16x4
	IopQSub32Sx2 IROp = 0x1400 + 350 // 有符号饱和减法32x2
	IopQSub64Sx1 IROp = 0x1400 + 351 // 有符号饱和减法64x1

	// 绝对值
	IopAbs8x8  IROp = 0x1400 + 352 // 绝对值8x8
	IopAbs16x4 IROp = 0x1400 + 353 // 绝对值16x4
	IopAbs32x2 IROp = 0x1400 + 354 // 绝对值32x2

	// 乘法(普通/有符号或无符号高半部分/多项式)
	IopMul8x8     IROp = 0x1400 + 355 // 乘法8x8
	IopMul16x4    IROp = 0x1400 + 356 // 乘法16x4
	IopMul32x2    IROp = 0x1400 + 357 // 乘法32x2
	IopMul32Fx2   IROp = 0x1400 + 358 // 浮点乘法32x2
	IopMulHi16Ux4 IROp = 0x1400 + 359 // 无符号高半部分乘法16x4
	IopMulHi16Sx4 IROp = 0x1400 + 360 // 有符号高半部分乘法16x4

	// 多项式乘法将参数视为{0,1}上多项式的系数
	IopPolynomialMul8x8 IROp = 0x1400 + 361 // 多项式乘法8x8

	// 向量饱和双倍乘法返回高半部分和向量饱和舍入双倍乘法返回高半部分
	// 这些IROp将两个向量中的对应元素相乘，结果加倍，并将最终结果的最高有效半部分放在目标向量中。
	// 结果被截断或舍入。如果任何结果溢出，它们将被饱和处理。
	IopQDMulHi16Sx4  IROp = 0x1400 + 362 // 饱和双倍乘法返回高半部分16x4
	IopQDMulHi32Sx2  IROp = 0x1400 + 363 // 饱和双倍乘法返回高半部分32x2
	IopQRDMulHi16Sx4 IROp = 0x1400 + 364 // 饱和舍入双倍乘法返回高半部分16x4
	IopQRDMulHi32Sx2 IROp = 0x1400 + 365 // 饱和舍入双倍乘法返回高半部分32x2

	// 平均值：注意：(arg1 + arg2 + 1) >>u 1
	IopAvg8Ux8  IROp = 0x1400 + 366 // 无符号平均值8x8
	IopAvg16Ux4 IROp = 0x1400 + 367 // 无符号平均值16x4

	// 最大值/最小值
	IopMax8Sx8  IROp = 0x1400 + 368 // 有符号最大值8x8
	IopMax16Sx4 IROp = 0x1400 + 369 // 有符号最大值16x4
	IopMax32Sx2 IROp = 0x1400 + 370 // 有符号最大值32x2
	IopMax8Ux8  IROp = 0x1400 + 371 // 无符号最大值8x8
	IopMax16Ux4 IROp = 0x1400 + 372 // 无符号最大值16x4
	IopMax32Ux2 IROp = 0x1400 + 373 // 无符号最大值32x2
	IopMin8Sx8  IROp = 0x1400 + 374 // 有符号最小值8x8
	IopMin16Sx4 IROp = 0x1400 + 375 // 有符号最小值16x4
	IopMin32Sx2 IROp = 0x1400 + 376 // 有符号最小值32x2
	IopMin8Ux8  IROp = 0x1400 + 377 // 无符号最小值8x8
	IopMin16Ux4 IROp = 0x1400 + 378 // 无符号最小值16x4
	IopMin32Ux2 IROp = 0x1400 + 379 // 无符号最小值32x2

	// 比较
	IopCmpEQ8x8   IROp = 0x1400 + 380 // 相等比较8x8
	IopCmpEQ16x4  IROp = 0x1400 + 381 // 相等比较16x4
	IopCmpEQ32x2  IROp = 0x1400 + 382 // 相等比较32x2
	IopCmpGT8Ux8  IROp = 0x1400 + 383 // 无符号大于比较8x8
	IopCmpGT16Ux4 IROp = 0x1400 + 384 // 无符号大于比较16x4
	IopCmpGT32Ux2 IROp = 0x1400 + 385 // 无符号大于比较32x2
	IopCmpGT8Sx8  IROp = 0x1400 + 386 // 有符号大于比较8x8
	IopCmpGT16Sx4 IROp = 0x1400 + 387 // 有符号大于比较16x4
	IopCmpGT32Sx2 IROp = 0x1400 + 388 // 有符号大于比较32x2

	// 计数：比特位1的数量/前导零/前导符号位（不包括最高位）
	IopCnt8x8  IROp = 0x1400 + 389 // 计数比特位中1的数量8x8
	IopClz8x8  IROp = 0x1400 + 390 // 计数前导零8x8
	IopClz16x4 IROp = 0x1400 + 391 // 计数前导零16x4
	IopClz32x2 IROp = 0x1400 + 392 // 计数前导零32x2
	IopCls8x8  IROp = 0x1400 + 393 // 计数前导符号位8x8
	IopCls16x4 IROp = 0x1400 + 394 // 计数前导符号位16x4
	IopCls32x2 IROp = 0x1400 + 395 // 计数前导符号位32x2
	IopClz64x2 IROp = 0x1400 + 396 // 计数前导零64x2

	// 向量计数尾随零
	IopCtz8x16 IROp = 0x1400 + 397 // 计数尾随零8x16
	IopCtz16x8 IROp = 0x1400 + 398 // 计数尾随零16x8
	IopCtz32x4 IROp = 0x1400 + 399 // 计数尾随零32x4
	IopCtz64x2 IROp = 0x1400 + 400 // 计数尾随零64x2

	// 向量x向量 移位/旋转
	IopShl8x8  IROp = 0x1400 + 401 // 左移8x8
	IopShl16x4 IROp = 0x1400 + 402 // 左移16x4
	IopShl32x2 IROp = 0x1400 + 403 // 左移32x2
	IopShr8x8  IROp = 0x1400 + 404 // 逻辑右移8x8
	IopShr16x4 IROp = 0x1400 + 405 // 逻辑右移16x4
	IopShr32x2 IROp = 0x1400 + 406 // 逻辑右移32x2
	IopSar8x8  IROp = 0x1400 + 407 // 算术右移8x8
	IopSar16x4 IROp = 0x1400 + 408 // 算术右移16x4
	IopSar32x2 IROp = 0x1400 + 409 // 算术右移32x2
	IopSal8x8  IROp = 0x1400 + 410 // 算术左移8x8
	IopSal16x4 IROp = 0x1400 + 411 // 算术左移16x4
	IopSal32x2 IROp = 0x1400 + 412 // 算术左移32x2
	IopSal64x1 IROp = 0x1400 + 413 // 算术左移64x1

	// 向量x标量 移位（移位量 :: Ity_I8）
	IopShlN8x8  IROp = 0x1400 + 414 // 标量左移8x8
	IopShlN16x4 IROp = 0x1400 + 415 // 标量左移16x4
	IopShlN32x2 IROp = 0x1400 + 416 // 标量左移32x2
	IopShrN8x8  IROp = 0x1400 + 417 // 标量逻辑右移8x8
	IopShrN16x4 IROp = 0x1400 + 418 // 标量逻辑右移16x4
	IopShrN32x2 IROp = 0x1400 + 419 // 标量逻辑右移32x2
	IopSarN8x8  IROp = 0x1400 + 420 // 标量算术右移8x8
	IopSarN16x4 IROp = 0x1400 + 421 // 标量算术右移16x4
	IopSarN32x2 IROp = 0x1400 + 422 // 标量算术右移32x2

	// 向量x向量 饱和移位
	IopQShl8x8  IROp = 0x1400 + 423 // 饱和左移8x8
	IopQShl16x4 IROp = 0x1400 + 424 // 饱和左移16x4
	IopQShl32x2 IROp = 0x1400 + 425 // 饱和左移32x2
	IopQShl64x1 IROp = 0x1400 + 426 // 饱和左移64x1
	IopQSal8x8  IROp = 0x1400 + 427 // 饱和算术左移8x8
	IopQSal16x4 IROp = 0x1400 + 428 // 饱和算术左移16x4
	IopQSal32x2 IROp = 0x1400 + 429 // 饱和算术左移32x2
	IopQSal64x1 IROp = 0x1400 + 430 // 饱和算术左移64x1

	// 向量x整数 饱和移位
	IopQShlNsatSU8x8  IROp = 0x1400 + 431 // 有符号到无符号饱和左移8x8
	IopQShlNsatSU16x4 IROp = 0x1400 + 432 // 有符号到无符号饱和左移16x4
	IopQShlNsatSU32x2 IROp = 0x1400 + 433 // 有符号到无符号饱和左移32x2
	IopQShlNsatSU64x1 IROp = 0x1400 + 434 // 有符号到无符号饱和左移64x1
	IopQShlNsatUU8x8  IROp = 0x1400 + 435 // 无符号到无符号饱和左移8x8
	IopQShlNsatUU16x4 IROp = 0x1400 + 436 // 无符号到无符号饱和左移16x4
	IopQShlNsatUU32x2 IROp = 0x1400 + 437 // 无符号到无符号饱和左移32x2
	IopQShlNsatUU64x1 IROp = 0x1400 + 438 // 无符号到无符号饱和左移64x1
	IopQShlNsatSS8x8  IROp = 0x1400 + 439 // 有符号到有符号饱和左移8x8
	IopQShlNsatSS16x4 IROp = 0x1400 + 440 // 有符号到有符号饱和左移16x4
	IopQShlNsatSS32x2 IROp = 0x1400 + 441 // 有符号到有符号饱和左移32x2
	IopQShlNsatSS64x1 IROp = 0x1400 + 442 // 有符号到有符号饱和左移64x1

	// 缩小（二元）
	// -- 将2xI64缩小为1xI64，高半部分来自左参数
	IopQNarrowBin16Sto8Ux8  IROp = 0x1400 + 443 // 有符号16位到无符号8位x8
	IopQNarrowBin16Sto8Sx8  IROp = 0x1400 + 444 // 有符号16位到有符号8位x8
	IopQNarrowBin32Sto16Sx4 IROp = 0x1400 + 445 // 有符号32位到有符号16位x4
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
	Op  IROp    /* 操作码 */
	Arg *IRExpr /* 操作数 */
}

// Load 表示从内存加载（普通加载，非 Load-Linked）
type Load struct {
	End  C.IREndness /* 字节序 */
	Ty   IRType      /* 加载值的类型 */
	Addr *IRExpr     /* 加载地址 */
}

// Const 表示常量表达式
type Const struct {
	Con *IRConst /* 常量本身 */
}

// CCall 表示调用纯C函数（无副作用）
type CCall struct {
	Cee   *C.IRCallee /* 要调用的函数 */
	RetTy IRType      /* 返回值类型 */
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

func GetIRTypeSize(irt IRType) int {
	switch irt {
	case ItyI1:
		return 1 // 虽然只有1位，但通常以字节为单位
	case ItyI8:
		return 1
	case ItyI16:
		return 2
	case ItyI32:
		return 4
	case ItyI64:
		return 8
	case ItyI128:
		return 16
	case ItyF16:
		return 2
	case ItyF32:
		return 4
	case ItyF64:
		return 8
	case ItyD32:
		return 4
	case ItyD64:
		return 8
	case ItyD128:
		return 16
	case ItyF128:
		return 16
	case ItyV128:
		return 16
	case ItyV256:
		return 32
	default:
		panic(fmt.Sprintf("unknown IRType size for type: %v", irt))
	}
}

func GetIRConstTagSize(ict IRConstTag) int {
	switch ict {
	case IcoU1:
		return 1 // 实际上只有 1 位，但分配为 1 字节
	case IcoU8:
		return 1
	case IcoU16:
		return 2
	case IcoU32:
		return 4
	case IcoU64:
		return 8
	case IcoF32, IcoF32i:
		return 4
	case IcoF64, IcoF64i:
		return 8
	case IcoV128:
		return 16
	case IcoV256:
		return 32
	default:
		panic("unknown IRConstTag size")
	}
}
