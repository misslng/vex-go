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
	IopINVALID                    IROp = 0x1400 // 5120
	IopAdd8                       IROp = 0x1401 // 5121
	IopAdd16                      IROp = 0x1402 // 5122
	IopAdd32                      IROp = 0x1403 // 5123
	IopAdd64                      IROp = 0x1404 // 5124
	IopSub8                       IROp = 0x1405 // 5125
	IopSub16                      IROp = 0x1406 // 5126
	IopSub32                      IROp = 0x1407 // 5127
	IopSub64                      IROp = 0x1408 // 5128
	IopMul8                       IROp = 0x1409 // 5129
	IopMul16                      IROp = 0x140A // 5130
	IopMul32                      IROp = 0x140B // 5131
	IopMul64                      IROp = 0x140C // 5132
	IopOr8                        IROp = 0x140D // 5133
	IopOr16                       IROp = 0x140E // 5134
	IopOr32                       IROp = 0x140F // 5135
	IopOr64                       IROp = 0x1410 // 5136
	IopAnd8                       IROp = 0x1411 // 5137
	IopAnd16                      IROp = 0x1412 // 5138
	IopAnd32                      IROp = 0x1413 // 5139
	IopAnd64                      IROp = 0x1414 // 5140
	IopXor8                       IROp = 0x1415 // 5141
	IopXor16                      IROp = 0x1416 // 5142
	IopXor32                      IROp = 0x1417 // 5143
	IopXor64                      IROp = 0x1418 // 5144
	IopShl8                       IROp = 0x1419 // 5145
	IopShl16                      IROp = 0x141A // 5146
	IopShl32                      IROp = 0x141B // 5147
	IopShl64                      IROp = 0x141C // 5148
	IopShr8                       IROp = 0x141D // 5149
	IopShr16                      IROp = 0x141E // 5150
	IopShr32                      IROp = 0x141F // 5151
	IopShr64                      IROp = 0x1420 // 5152
	IopSar8                       IROp = 0x1421 // 5153
	IopSar16                      IROp = 0x1422 // 5154
	IopSar32                      IROp = 0x1423 // 5155
	IopSar64                      IROp = 0x1424 // 5156
	IopCmpEQ8                     IROp = 0x1425 // 5157
	IopCmpEQ16                    IROp = 0x1426 // 5158
	IopCmpEQ32                    IROp = 0x1427 // 5159
	IopCmpEQ64                    IROp = 0x1428 // 5160
	IopCmpNE8                     IROp = 0x1429 // 5161
	IopCmpNE16                    IROp = 0x142A // 5162
	IopCmpNE32                    IROp = 0x142B // 5163
	IopCmpNE64                    IROp = 0x142C // 5164
	IopNot8                       IROp = 0x142D // 5165
	IopNot16                      IROp = 0x142E // 5166
	IopNot32                      IROp = 0x142F // 5167
	IopNot64                      IROp = 0x1430 // 5168
	IopCasCmpEQ8                  IROp = 0x1431 // 5169
	IopCasCmpEQ16                 IROp = 0x1432 // 5170
	IopCasCmpEQ32                 IROp = 0x1433 // 5171
	IopCasCmpEQ64                 IROp = 0x1434 // 5172
	IopCasCmpNE8                  IROp = 0x1435 // 5173
	IopCasCmpNE16                 IROp = 0x1436 // 5174
	IopCasCmpNE32                 IROp = 0x1437 // 5175
	IopCasCmpNE64                 IROp = 0x1438 // 5176
	IopExpCmpNE8                  IROp = 0x1439 // 5177
	IopExpCmpNE16                 IROp = 0x143A // 5178
	IopExpCmpNE32                 IROp = 0x143B // 5179
	IopExpCmpNE64                 IROp = 0x143C // 5180
	IopMullS8                     IROp = 0x143D // 5181
	IopMullS16                    IROp = 0x143E // 5182
	IopMullS32                    IROp = 0x143F // 5183
	IopMullS64                    IROp = 0x1440 // 5184
	IopMullU8                     IROp = 0x1441 // 5185
	IopMullU16                    IROp = 0x1442 // 5186
	IopMullU32                    IROp = 0x1443 // 5187
	IopMullU64                    IROp = 0x1444 // 5188
	IopClz64                      IROp = 0x1445 // 5189
	IopClz32                      IROp = 0x1446 // 5190
	IopCtz64                      IROp = 0x1447 // 5191
	IopCtz32                      IROp = 0x1448 // 5192
	IopCmpLT32S                   IROp = 0x1449 // 5193
	IopCmpLT64S                   IROp = 0x144A // 5194
	IopCmpLE32S                   IROp = 0x144B // 5195
	IopCmpLE64S                   IROp = 0x144C // 5196
	IopCmpLT32U                   IROp = 0x144D // 5197
	IopCmpLT64U                   IROp = 0x144E // 5198
	IopCmpLE32U                   IROp = 0x144F // 5199
	IopCmpLE64U                   IROp = 0x1450 // 5200
	IopCmpNEZ8                    IROp = 0x1451 // 5201
	IopCmpNEZ16                   IROp = 0x1452 // 5202
	IopCmpNEZ32                   IROp = 0x1453 // 5203
	IopCmpNEZ64                   IROp = 0x1454 // 5204
	IopCmpwNEZ32                  IROp = 0x1455 // 5205
	IopCmpwNEZ64                  IROp = 0x1456 // 5206
	IopLeft8                      IROp = 0x1457 // 5207
	IopLeft16                     IROp = 0x1458 // 5208
	IopLeft32                     IROp = 0x1459 // 5209
	IopLeft64                     IROp = 0x145A // 5210
	IopMax32U                     IROp = 0x145B // 5211
	IopCmpORD32U                  IROp = 0x145C // 5212
	IopCmpORD64U                  IROp = 0x145D // 5213
	IopCmpORD32S                  IROp = 0x145E // 5214
	IopCmpORD64S                  IROp = 0x145F // 5215
	IopDivU32                     IROp = 0x1460 // :: I32,I32 -> I32 (simple div, no mod)
	IopDivS32                     IROp = 0x1461 // ditto, signed
	IopDivU64                     IROp = 0x1462 // :: I64,I64 -> I64 (simple div, no mod)
	IopDivS64                     IROp = 0x1463 // ditto, signed
	IopDivU64E                    IROp = 0x1464 // :: I64,I64 -> I64 (dividend is 64-bit arg (hi)
	IopDivS64E                    IROp = 0x1465 // ditto, signed
	IopDivU32E                    IROp = 0x1466 // :: I32,I32 -> I32 (dividend is 32-bit arg (hi)
	IopDivS32E                    IROp = 0x1467 // ditto, signed
	IopDivModU64to32              IROp = 0x1468 // :: I64,I32 -> I64
	IopDivModS64to32              IROp = 0x1469 // ditto, signed
	IopDivModU128to64             IROp = 0x146A // :: V128,I64 -> V128
	IopDivModS128to64             IROp = 0x146B // ditto, signed
	IopDivModS64to64              IROp = 0x146C // :: I64,I64 -> I128
	Iop8Uto16                     IROp = 0x146D // 5229
	Iop8Uto32                     IROp = 0x146E // 5230
	Iop8Uto64                     IROp = 0x146F // 5231
	Iop16Uto32                    IROp = 0x1470 // 5232
	Iop16Uto64                    IROp = 0x1471 // 5233
	Iop32Uto64                    IROp = 0x1472 // 5234
	Iop8Sto16                     IROp = 0x1473 // 5235
	Iop8Sto32                     IROp = 0x1474 // 5236
	Iop8Sto64                     IROp = 0x1475 // 5237
	Iop16Sto32                    IROp = 0x1476 // 5238
	Iop16Sto64                    IROp = 0x1477 // 5239
	Iop32Sto64                    IROp = 0x1478 // 5240
	Iop64to8                      IROp = 0x1479 // 5241
	Iop32to8                      IROp = 0x147A // 5242
	Iop64to16                     IROp = 0x147B // 5243
	Iop16to8                      IROp = 0x147C // :: I16 -> I8, low half
	Iop16HIto8                    IROp = 0x147D // :: I16 -> I8, high half
	Iop8HLto16                    IROp = 0x147E // :: (I8,I8) -> I16
	Iop32to16                     IROp = 0x147F // :: I32 -> I16, low half
	Iop32HIto16                   IROp = 0x1480 // :: I32 -> I16, high half
	Iop16HLto32                   IROp = 0x1481 // :: (I16,I16) -> I32
	Iop64to32                     IROp = 0x1482 // :: I64 -> I32, low half
	Iop64HIto32                   IROp = 0x1483 // :: I64 -> I32, high half
	Iop32HLto64                   IROp = 0x1484 // :: (I32,I32) -> I64
	Iop128to64                    IROp = 0x1485 // :: I128 -> I64, low half
	Iop128HIto64                  IROp = 0x1486 // :: I128 -> I64, high half
	Iop64HLto128                  IROp = 0x1487 // :: (I64,I64) -> I128
	IopNot1                       IROp = 0x1488 // 5256
	Iop32to1                      IROp = 0x1489 // 5257
	Iop64to1                      IROp = 0x148A // 5258
	Iop1Uto8                      IROp = 0x148B // 5259
	Iop1Uto32                     IROp = 0x148C // 5260
	Iop1Uto64                     IROp = 0x148D // 5261
	Iop1Sto8                      IROp = 0x148E // 5262
	Iop1Sto16                     IROp = 0x148F // 5263
	Iop1Sto32                     IROp = 0x1490 // 5264
	Iop1Sto64                     IROp = 0x1491 // 5265
	IopAddF64                     IROp = 0x1492 // 5266
	IopSubF64                     IROp = 0x1493 // 5267
	IopMulF64                     IROp = 0x1494 // 5268
	IopDivF64                     IROp = 0x1495 // 5269
	IopAddF32                     IROp = 0x1496 // 5270
	IopSubF32                     IROp = 0x1497 // 5271
	IopMulF32                     IROp = 0x1498 // 5272
	IopDivF32                     IROp = 0x1499 // 5273
	IopAddF64r32                  IROp = 0x149A // 5274
	IopSubF64r32                  IROp = 0x149B // 5275
	IopMulF64r32                  IROp = 0x149C // 5276
	IopDivF64r32                  IROp = 0x149D // 5277
	IopNegF64                     IROp = 0x149E // 5278
	IopAbsF64                     IROp = 0x149F // 5279
	IopNegF32                     IROp = 0x14A0 // 5280
	IopAbsF32                     IROp = 0x14A1 // 5281
	IopSqrtF64                    IROp = 0x14A2 // 5282
	IopSqrtF32                    IROp = 0x14A3 // 5283
	IopCmpF64                     IROp = 0x14A4 // 5284
	IopCmpF32                     IROp = 0x14A5 // 5285
	IopCmpF128                    IROp = 0x14A6 // 5286
	IopF64toI16S                  IROp = 0x14A7 // 5287
	IopF64toI32S                  IROp = 0x14A8 // 5288
	IopF64toI64S                  IROp = 0x14A9 // 5289
	IopF64toI64U                  IROp = 0x14AA // 5290
	IopF64toI32U                  IROp = 0x14AB // 5291
	IopI32StoF64                  IROp = 0x14AC // 5292
	IopI64StoF64                  IROp = 0x14AD // 5293
	IopI64UtoF64                  IROp = 0x14AE // 5294
	IopI64UtoF32                  IROp = 0x14AF // 5295
	IopI32UtoF32                  IROp = 0x14B0 // 5296
	IopI32UtoF64                  IROp = 0x14B1 // 5297
	IopF32toI32S                  IROp = 0x14B2 // 5298
	IopF32toI64S                  IROp = 0x14B3 // 5299
	IopF32toI32U                  IROp = 0x14B4 // 5300
	IopF32toI64U                  IROp = 0x14B5 // 5301
	IopI32StoF32                  IROp = 0x14B6 // 5302
	IopI64StoF32                  IROp = 0x14B7 // 5303
	IopF32toF64                   IROp = 0x14B8 // 5304
	IopF64toF32                   IROp = 0x14B9 // 5305
	IopReinterpF64asI64           IROp = 0x14BA // 5306
	IopReinterpI64asF64           IROp = 0x14BB // 5307
	IopReinterpF32asI32           IROp = 0x14BC // 5308
	IopReinterpI32asF32           IROp = 0x14BD // 5309
	IopF64HLtoF128                IROp = 0x14BE // 5310
	IopF128HItoF64                IROp = 0x14BF // 5311
	IopF128LOtoF64                IROp = 0x14C0 // 5312
	IopAddF128                    IROp = 0x14C1 // 5313
	IopSubF128                    IROp = 0x14C2 // 5314
	IopMulF128                    IROp = 0x14C3 // 5315
	IopDivF128                    IROp = 0x14C4 // 5316
	IopMAddF128                   IROp = 0x14C5 // (A * B) + C
	IopMSubF128                   IROp = 0x14C6 // (A * B) - C
	IopNegMAddF128                IROp = 0x14C7 // -((A * B) + C)
	IopNegMSubF128                IROp = 0x14C8 // -((A * B) - C)
	IopNegF128                    IROp = 0x14C9 // 5321
	IopAbsF128                    IROp = 0x14CA // 5322
	IopSqrtF128                   IROp = 0x14CB // 5323
	IopI32StoF128                 IROp = 0x14CC // 5324
	IopI64StoF128                 IROp = 0x14CD // 5325
	IopI32UtoF128                 IROp = 0x14CE // 5326
	IopI64UtoF128                 IROp = 0x14CF // 5327
	IopF32toF128                  IROp = 0x14D0 // 5328
	IopF64toF128                  IROp = 0x14D1 // 5329
	IopF128toI32S                 IROp = 0x14D2 // 5330
	IopF128toI64S                 IROp = 0x14D3 // 5331
	IopF128toI32U                 IROp = 0x14D4 // 5332
	IopF128toI64U                 IROp = 0x14D5 // 5333
	IopF128toI128S                IROp = 0x14D6 // 5334
	IopF128toF64                  IROp = 0x14D7 // 5335
	IopF128toF32                  IROp = 0x14D8 // 5336
	IopRndF128                    IROp = 0x14D9 // 5337
	IopTruncF128toI32S            IROp = 0x14DA // 5338
	IopTruncF128toI32U            IROp = 0x14DB // 5339
	IopTruncF128toI64U            IROp = 0x14DC // 5340
	IopTruncF128toI64S            IROp = 0x14DD // 5341
	IopAtanF64                    IROp = 0x14DE // 5342
	IopYl2xF64                    IROp = 0x14DF // 5343
	IopYl2xp1F64                  IROp = 0x14E0 // 5344
	IopPRemF64                    IROp = 0x14E1 // 5345
	IopPRemC3210F64               IROp = 0x14E2 // 5346
	IopPRem1F64                   IROp = 0x14E3 // 5347
	IopPRem1C3210F64              IROp = 0x14E4 // 5348
	IopScaleF64                   IROp = 0x14E5 // 5349
	IopSinF64                     IROp = 0x14E6 // 5350
	IopCosF64                     IROp = 0x14E7 // 5351
	IopTanF64                     IROp = 0x14E8 // 5352
	Iop2xm1F64                    IROp = 0x14E9 // 5353
	IopRoundF128toInt             IROp = 0x14EA // 5354
	IopRoundF64toInt              IROp = 0x14EB // 5355
	IopRoundF32toInt              IROp = 0x14EC // 5356
	IopMAddF32                    IROp = 0x14ED // 5357
	IopMSubF32                    IROp = 0x14EE // 5358
	IopMAddF64                    IROp = 0x14EF // 5359
	IopMSubF64                    IROp = 0x14F0 // 5360
	IopMAddF64r32                 IROp = 0x14F1 // 5361
	IopMSubF64r32                 IROp = 0x14F2 // 5362
	IopRSqrtEst5GoodF64           IROp = 0x14F3 // 5363
	IopRoundF64toF64NEAREST       IROp = 0x14F4 // 5364
	IopRoundF64toF64NegINF        IROp = 0x14F5 // 5365
	IopRoundF64toF64PosINF        IROp = 0x14F6 // 5366
	IopRoundF64toF64ZERO          IROp = 0x14F7 // 5367
	IopTruncF64asF32              IROp = 0x14F8 // 5368
	IopRoundF64toF32              IROp = 0x14F9 // 5369
	IopRecpExpF64                 IROp = 0x14FA // 5370
	IopRecpExpF32                 IROp = 0x14FB // 5371
	IopMaxNumF64                  IROp = 0x14FC // 5372
	IopMinNumF64                  IROp = 0x14FD // 5373
	IopMaxNumF32                  IROp = 0x14FE // 5374
	IopMinNumF32                  IROp = 0x14FF // 5375
	IopF16toF64                   IROp = 0x1500 // 5376
	IopF64toF16                   IROp = 0x1501 // 5377
	IopF16toF32                   IROp = 0x1502 // 5378
	IopF32toF16                   IROp = 0x1503 // 5379
	IopQAdd32S                    IROp = 0x1504 // 5380
	IopQSub32S                    IROp = 0x1505 // 5381
	IopAdd16x2                    IROp = 0x1506 // 5382
	IopSub16x2                    IROp = 0x1507 // 5383
	IopQAdd16Sx2                  IROp = 0x1508 // 5384
	IopQAdd16Ux2                  IROp = 0x1509 // 5385
	IopQSub16Sx2                  IROp = 0x150A // 5386
	IopQSub16Ux2                  IROp = 0x150B // 5387
	IopHAdd16Ux2                  IROp = 0x150C // 5388
	IopHAdd16Sx2                  IROp = 0x150D // 5389
	IopHSub16Ux2                  IROp = 0x150E // 5390
	IopHSub16Sx2                  IROp = 0x150F // 5391
	IopAdd8x4                     IROp = 0x1510 // 5392
	IopSub8x4                     IROp = 0x1511 // 5393
	IopQAdd8Sx4                   IROp = 0x1512 // 5394
	IopQAdd8Ux4                   IROp = 0x1513 // 5395
	IopQSub8Sx4                   IROp = 0x1514 // 5396
	IopQSub8Ux4                   IROp = 0x1515 // 5397
	IopHAdd8Ux4                   IROp = 0x1516 // 5398
	IopHAdd8Sx4                   IROp = 0x1517 // 5399
	IopHSub8Ux4                   IROp = 0x1518 // 5400
	IopHSub8Sx4                   IROp = 0x1519 // 5401
	IopSad8Ux4                    IROp = 0x151A // 5402
	IopCmpNEZ16x2                 IROp = 0x151B // 5403
	IopCmpNEZ8x4                  IROp = 0x151C // 5404
	IopI32UtoFx2                  IROp = 0x151D // 5405
	IopI32StoFx2                  IROp = 0x151E // 5406
	IopFtoI32Ux2RZ                IROp = 0x151F // 5407
	IopFtoI32Sx2RZ                IROp = 0x1520 // 5408
	IopF32ToFixed32Ux2RZ          IROp = 0x1521 // 5409
	IopF32ToFixed32Sx2RZ          IROp = 0x1522 // 5410
	IopFixed32UToF32x2RN          IROp = 0x1523 // 5411
	IopFixed32SToF32x2RN          IROp = 0x1524 // 5412
	IopMax32Fx2                   IROp = 0x1525 // 5413
	IopMin32Fx2                   IROp = 0x1526 // 5414
	IopPwMax32Fx2                 IROp = 0x1527 // 5415
	IopPwMin32Fx2                 IROp = 0x1528 // 5416
	IopCmpEQ32Fx2                 IROp = 0x1529 // 5417
	IopCmpGT32Fx2                 IROp = 0x152A // 5418
	IopCmpGE32Fx2                 IROp = 0x152B // 5419
	IopRecipEst32Fx2              IROp = 0x152C // 5420
	IopRecipStep32Fx2             IROp = 0x152D // 5421
	IopRSqrtEst32Fx2              IROp = 0x152E // 5422
	IopRSqrtStep32Fx2             IROp = 0x152F // 5423
	IopNeg32Fx2                   IROp = 0x1530 // 5424
	IopAbs32Fx2                   IROp = 0x1531 // 5425
	IopCmpNEZ8x8                  IROp = 0x1532 // 5426
	IopCmpNEZ16x4                 IROp = 0x1533 // 5427
	IopCmpNEZ32x2                 IROp = 0x1534 // 5428
	IopAdd8x8                     IROp = 0x1535 // 5429
	IopAdd16x4                    IROp = 0x1536 // 5430
	IopAdd32x2                    IROp = 0x1537 // 5431
	IopQAdd8Ux8                   IROp = 0x1538 // 5432
	IopQAdd16Ux4                  IROp = 0x1539 // 5433
	IopQAdd32Ux2                  IROp = 0x153A // 5434
	IopQAdd64Ux1                  IROp = 0x153B // 5435
	IopQAdd8Sx8                   IROp = 0x153C // 5436
	IopQAdd16Sx4                  IROp = 0x153D // 5437
	IopQAdd32Sx2                  IROp = 0x153E // 5438
	IopQAdd64Sx1                  IROp = 0x153F // 5439
	IopPwAdd8x8                   IROp = 0x1540 // 5440
	IopPwAdd16x4                  IROp = 0x1541 // 5441
	IopPwAdd32x2                  IROp = 0x1542 // 5442
	IopPwMax8Sx8                  IROp = 0x1543 // 5443
	IopPwMax16Sx4                 IROp = 0x1544 // 5444
	IopPwMax32Sx2                 IROp = 0x1545 // 5445
	IopPwMax8Ux8                  IROp = 0x1546 // 5446
	IopPwMax16Ux4                 IROp = 0x1547 // 5447
	IopPwMax32Ux2                 IROp = 0x1548 // 5448
	IopPwMin8Sx8                  IROp = 0x1549 // 5449
	IopPwMin16Sx4                 IROp = 0x154A // 5450
	IopPwMin32Sx2                 IROp = 0x154B // 5451
	IopPwMin8Ux8                  IROp = 0x154C // 5452
	IopPwMin16Ux4                 IROp = 0x154D // 5453
	IopPwMin32Ux2                 IROp = 0x154E // 5454
	IopPwAddL8Ux8                 IROp = 0x154F // 5455
	IopPwAddL16Ux4                IROp = 0x1550 // 5456
	IopPwAddL32Ux2                IROp = 0x1551 // 5457
	IopPwAddL8Sx8                 IROp = 0x1552 // 5458
	IopPwAddL16Sx4                IROp = 0x1553 // 5459
	IopPwAddL32Sx2                IROp = 0x1554 // 5460
	IopSub8x8                     IROp = 0x1555 // 5461
	IopSub16x4                    IROp = 0x1556 // 5462
	IopSub32x2                    IROp = 0x1557 // 5463
	IopQSub8Ux8                   IROp = 0x1558 // 5464
	IopQSub16Ux4                  IROp = 0x1559 // 5465
	IopQSub32Ux2                  IROp = 0x155A // 5466
	IopQSub64Ux1                  IROp = 0x155B // 5467
	IopQSub8Sx8                   IROp = 0x155C // 5468
	IopQSub16Sx4                  IROp = 0x155D // 5469
	IopQSub32Sx2                  IROp = 0x155E // 5470
	IopQSub64Sx1                  IROp = 0x155F // 5471
	IopAbs8x8                     IROp = 0x1560 // 5472
	IopAbs16x4                    IROp = 0x1561 // 5473
	IopAbs32x2                    IROp = 0x1562 // 5474
	IopMul8x8                     IROp = 0x1563 // 5475
	IopMul16x4                    IROp = 0x1564 // 5476
	IopMul32x2                    IROp = 0x1565 // 5477
	IopMul32Fx2                   IROp = 0x1566 // 5478
	IopMulHi16Ux4                 IROp = 0x1567 // 5479
	IopMulHi16Sx4                 IROp = 0x1568 // 5480
	IopPolynomialMul8x8           IROp = 0x1569 // 5481
	IopQDMulHi16Sx4               IROp = 0x156A // 5482
	IopQDMulHi32Sx2               IROp = 0x156B // 5483
	IopQRDMulHi16Sx4              IROp = 0x156C // 5484
	IopQRDMulHi32Sx2              IROp = 0x156D // 5485
	IopAvg8Ux8                    IROp = 0x156E // 5486
	IopAvg16Ux4                   IROp = 0x156F // 5487
	IopMax8Sx8                    IROp = 0x1570 // 5488
	IopMax16Sx4                   IROp = 0x1571 // 5489
	IopMax32Sx2                   IROp = 0x1572 // 5490
	IopMax8Ux8                    IROp = 0x1573 // 5491
	IopMax16Ux4                   IROp = 0x1574 // 5492
	IopMax32Ux2                   IROp = 0x1575 // 5493
	IopMin8Sx8                    IROp = 0x1576 // 5494
	IopMin16Sx4                   IROp = 0x1577 // 5495
	IopMin32Sx2                   IROp = 0x1578 // 5496
	IopMin8Ux8                    IROp = 0x1579 // 5497
	IopMin16Ux4                   IROp = 0x157A // 5498
	IopMin32Ux2                   IROp = 0x157B // 5499
	IopCmpEQ8x8                   IROp = 0x157C // 5500
	IopCmpEQ16x4                  IROp = 0x157D // 5501
	IopCmpEQ32x2                  IROp = 0x157E // 5502
	IopCmpGT8Ux8                  IROp = 0x157F // 5503
	IopCmpGT16Ux4                 IROp = 0x1580 // 5504
	IopCmpGT32Ux2                 IROp = 0x1581 // 5505
	IopCmpGT8Sx8                  IROp = 0x1582 // 5506
	IopCmpGT16Sx4                 IROp = 0x1583 // 5507
	IopCmpGT32Sx2                 IROp = 0x1584 // 5508
	IopCnt8x8                     IROp = 0x1585 // 5509
	IopClz8x8                     IROp = 0x1586 // 5510
	IopClz16x4                    IROp = 0x1587 // 5511
	IopClz32x2                    IROp = 0x1588 // 5512
	IopCls8x8                     IROp = 0x1589 // 5513
	IopCls16x4                    IROp = 0x158A // 5514
	IopCls32x2                    IROp = 0x158B // 5515
	IopClz64x2                    IROp = 0x158C // 5516
	IopCtz8x16                    IROp = 0x158D // 5517
	IopCtz16x8                    IROp = 0x158E // 5518
	IopCtz32x4                    IROp = 0x158F // 5519
	IopCtz64x2                    IROp = 0x1590 // 5520
	IopShl8x8                     IROp = 0x1591 // 5521
	IopShl16x4                    IROp = 0x1592 // 5522
	IopShl32x2                    IROp = 0x1593 // 5523
	IopShr8x8                     IROp = 0x1594 // 5524
	IopShr16x4                    IROp = 0x1595 // 5525
	IopShr32x2                    IROp = 0x1596 // 5526
	IopSar8x8                     IROp = 0x1597 // 5527
	IopSar16x4                    IROp = 0x1598 // 5528
	IopSar32x2                    IROp = 0x1599 // 5529
	IopSal8x8                     IROp = 0x159A // 5530
	IopSal16x4                    IROp = 0x159B // 5531
	IopSal32x2                    IROp = 0x159C // 5532
	IopSal64x1                    IROp = 0x159D // 5533
	IopShlN8x8                    IROp = 0x159E // 5534
	IopShlN16x4                   IROp = 0x159F // 5535
	IopShlN32x2                   IROp = 0x15A0 // 5536
	IopShrN8x8                    IROp = 0x15A1 // 5537
	IopShrN16x4                   IROp = 0x15A2 // 5538
	IopShrN32x2                   IROp = 0x15A3 // 5539
	IopSarN8x8                    IROp = 0x15A4 // 5540
	IopSarN16x4                   IROp = 0x15A5 // 5541
	IopSarN32x2                   IROp = 0x15A6 // 5542
	IopQShl8x8                    IROp = 0x15A7 // 5543
	IopQShl16x4                   IROp = 0x15A8 // 5544
	IopQShl32x2                   IROp = 0x15A9 // 5545
	IopQShl64x1                   IROp = 0x15AA // 5546
	IopQSal8x8                    IROp = 0x15AB // 5547
	IopQSal16x4                   IROp = 0x15AC // 5548
	IopQSal32x2                   IROp = 0x15AD // 5549
	IopQSal64x1                   IROp = 0x15AE // 5550
	IopQShlNsatSU8x8              IROp = 0x15AF // 5551
	IopQShlNsatSU16x4             IROp = 0x15B0 // 5552
	IopQShlNsatSU32x2             IROp = 0x15B1 // 5553
	IopQShlNsatSU64x1             IROp = 0x15B2 // 5554
	IopQShlNsatUU8x8              IROp = 0x15B3 // 5555
	IopQShlNsatUU16x4             IROp = 0x15B4 // 5556
	IopQShlNsatUU32x2             IROp = 0x15B5 // 5557
	IopQShlNsatUU64x1             IROp = 0x15B6 // 5558
	IopQShlNsatSS8x8              IROp = 0x15B7 // 5559
	IopQShlNsatSS16x4             IROp = 0x15B8 // 5560
	IopQShlNsatSS32x2             IROp = 0x15B9 // 5561
	IopQShlNsatSS64x1             IROp = 0x15BA // 5562
	IopQNarrowBin16Sto8Ux8        IROp = 0x15BB // 5563
	IopQNarrowBin16Sto8Sx8        IROp = 0x15BC // 5564
	IopQNarrowBin32Sto16Sx4       IROp = 0x15BD // 5565
	IopNarrowBin16to8x8           IROp = 0x15BE // 5566
	IopNarrowBin32to16x4          IROp = 0x15BF // 5567
	IopInterleaveHI8x8            IROp = 0x15C0 // 5568
	IopInterleaveHI16x4           IROp = 0x15C1 // 5569
	IopInterleaveHI32x2           IROp = 0x15C2 // 5570
	IopInterleaveLO8x8            IROp = 0x15C3 // 5571
	IopInterleaveLO16x4           IROp = 0x15C4 // 5572
	IopInterleaveLO32x2           IROp = 0x15C5 // 5573
	IopInterleaveOddLanes8x8      IROp = 0x15C6 // 5574
	IopInterleaveEvenLanes8x8     IROp = 0x15C7 // 5575
	IopInterleaveOddLanes16x4     IROp = 0x15C8 // 5576
	IopInterleaveEvenLanes16x4    IROp = 0x15C9 // 5577
	IopCatOddLanes8x8             IROp = 0x15CA // 5578
	IopCatOddLanes16x4            IROp = 0x15CB // 5579
	IopCatEvenLanes8x8            IROp = 0x15CC // 5580
	IopCatEvenLanes16x4           IROp = 0x15CD // 5581
	IopGetElem8x8                 IROp = 0x15CE // 5582
	IopGetElem16x4                IROp = 0x15CF // 5583
	IopGetElem32x2                IROp = 0x15D0 // 5584
	IopSetElem8x8                 IROp = 0x15D1 // 5585
	IopSetElem16x4                IROp = 0x15D2 // 5586
	IopSetElem32x2                IROp = 0x15D3 // 5587
	IopDup8x8                     IROp = 0x15D4 // 5588
	IopDup16x4                    IROp = 0x15D5 // 5589
	IopDup32x2                    IROp = 0x15D6 // 5590
	IopSlice64                    IROp = 0x15D7 // (I64, I64, I8) -> I64
	IopReverse8sIn16x4            IROp = 0x15D8 // 5592
	IopReverse8sIn32x2            IROp = 0x15D9 // 5593
	IopReverse16sIn32x2           IROp = 0x15DA // 5594
	IopReverse8sIn64x1            IROp = 0x15DB // 5595
	IopReverse16sIn64x1           IROp = 0x15DC // 5596
	IopReverse32sIn64x1           IROp = 0x15DD // 5597
	IopPerm8x8                    IROp = 0x15DE // 5598
	IopGetMSBs8x8                 IROp = 0x15DF // 5599
	IopRecipEst32Ux2              IROp = 0x15E0 // 5600
	IopRSqrtEst32Ux2              IROp = 0x15E1 // 5601
	IopAddD64                     IROp = 0x15E2 // 5602
	IopSubD64                     IROp = 0x15E3 // 5603
	IopMulD64                     IROp = 0x15E4 // 5604
	IopDivD64                     IROp = 0x15E5 // 5605
	IopAddD128                    IROp = 0x15E6 // 5606
	IopSubD128                    IROp = 0x15E7 // 5607
	IopMulD128                    IROp = 0x15E8 // 5608
	IopDivD128                    IROp = 0x15E9 // 5609
	IopShlD64                     IROp = 0x15EA // 5610
	IopShrD64                     IROp = 0x15EB // 5611
	IopShlD128                    IROp = 0x15EC // 5612
	IopShrD128                    IROp = 0x15ED // 5613
	IopD32toD64                   IROp = 0x15EE // 5614
	IopD64toD128                  IROp = 0x15EF // 5615
	IopI32StoD128                 IROp = 0x15F0 // 5616
	IopI32UtoD128                 IROp = 0x15F1 // 5617
	IopI64StoD128                 IROp = 0x15F2 // 5618
	IopI64UtoD128                 IROp = 0x15F3 // 5619
	IopD64toD32                   IROp = 0x15F4 // 5620
	IopD128toD64                  IROp = 0x15F5 // 5621
	IopI32StoD64                  IROp = 0x15F6 // 5622
	IopI32UtoD64                  IROp = 0x15F7 // 5623
	IopI64StoD64                  IROp = 0x15F8 // 5624
	IopI64UtoD64                  IROp = 0x15F9 // 5625
	IopD64toI32S                  IROp = 0x15FA // 5626
	IopD64toI32U                  IROp = 0x15FB // 5627
	IopD64toI64S                  IROp = 0x15FC // 5628
	IopD64toI64U                  IROp = 0x15FD // 5629
	IopD128toI32S                 IROp = 0x15FE // 5630
	IopD128toI32U                 IROp = 0x15FF // 5631
	IopD128toI64S                 IROp = 0x1600 // 5632
	IopD128toI64U                 IROp = 0x1601 // 5633
	IopF32toD32                   IROp = 0x1602 // 5634
	IopF32toD64                   IROp = 0x1603 // 5635
	IopF32toD128                  IROp = 0x1604 // 5636
	IopF64toD32                   IROp = 0x1605 // 5637
	IopF64toD64                   IROp = 0x1606 // 5638
	IopF64toD128                  IROp = 0x1607 // 5639
	IopF128toD32                  IROp = 0x1608 // 5640
	IopF128toD64                  IROp = 0x1609 // 5641
	IopF128toD128                 IROp = 0x160A // 5642
	IopD32toF32                   IROp = 0x160B // 5643
	IopD32toF64                   IROp = 0x160C // 5644
	IopD32toF128                  IROp = 0x160D // 5645
	IopD64toF32                   IROp = 0x160E // 5646
	IopD64toF64                   IROp = 0x160F // 5647
	IopD64toF128                  IROp = 0x1610 // 5648
	IopD128toF32                  IROp = 0x1611 // 5649
	IopD128toF64                  IROp = 0x1612 // 5650
	IopD128toF128                 IROp = 0x1613 // 5651
	IopRoundD64toInt              IROp = 0x1614 // 5652
	IopRoundD128toInt             IROp = 0x1615 // 5653
	IopCmpD64                     IROp = 0x1616 // 5654
	IopCmpD128                    IROp = 0x1617 // 5655
	IopCmpExpD64                  IROp = 0x1618 // 5656
	IopCmpExpD128                 IROp = 0x1619 // 5657
	IopQuantizeD64                IROp = 0x161A // 5658
	IopQuantizeD128               IROp = 0x161B // 5659
	IopSignificanceRoundD64       IROp = 0x161C // 5660
	IopSignificanceRoundD128      IROp = 0x161D // 5661
	IopExtractExpD64              IROp = 0x161E // 5662
	IopExtractExpD128             IROp = 0x161F // 5663
	IopExtractSigD64              IROp = 0x1620 // 5664
	IopExtractSigD128             IROp = 0x1621 // 5665
	IopInsertExpD64               IROp = 0x1622 // 5666
	IopInsertExpD128              IROp = 0x1623 // 5667
	IopD64HLtoD128                IROp = 0x1624 // 5668
	IopD128HItoD64                IROp = 0x1625 // 5669
	IopD128LOtoD64                IROp = 0x1626 // 5670
	IopDPBtoBCD                   IROp = 0x1627 // 5671
	IopBCDtoDPB                   IROp = 0x1628 // 5672
	IopBCDAdd                     IROp = 0x1629 // 5673
	IopBCDSub                     IROp = 0x162A // 5674
	IopI128StoBCD128              IROp = 0x162B // 5675
	IopBCD128toI128S              IROp = 0x162C // 5676
	IopReinterpI64asD64           IROp = 0x162D // 5677
	IopReinterpD64asI64           IROp = 0x162E // 5678
	IopAdd32Fx4                   IROp = 0x162F // 5679
	IopSub32Fx4                   IROp = 0x1630 // 5680
	IopMul32Fx4                   IROp = 0x1631 // 5681
	IopDiv32Fx4                   IROp = 0x1632 // 5682
	IopMax32Fx4                   IROp = 0x1633 // 5683
	IopMin32Fx4                   IROp = 0x1634 // 5684
	IopAdd32Fx2                   IROp = 0x1635 // 5685
	IopSub32Fx2                   IROp = 0x1636 // 5686
	IopCmpEQ32Fx4                 IROp = 0x1637 // 5687
	IopCmpLT32Fx4                 IROp = 0x1638 // 5688
	IopCmpLE32Fx4                 IROp = 0x1639 // 5689
	IopCmpUN32Fx4                 IROp = 0x163A // 5690
	IopCmpGT32Fx4                 IROp = 0x163B // 5691
	IopCmpGE32Fx4                 IROp = 0x163C // 5692
	IopPwMax32Fx4                 IROp = 0x163D // 5693
	IopPwMin32Fx4                 IROp = 0x163E // 5694
	IopAbs32Fx4                   IROp = 0x163F // 5695
	IopNeg32Fx4                   IROp = 0x1640 // 5696
	IopSqrt32Fx4                  IROp = 0x1641 // 5697
	IopRecipEst32Fx4              IROp = 0x1642 // 5698
	IopRecipStep32Fx4             IROp = 0x1643 // 5699
	IopRSqrtEst32Fx4              IROp = 0x1644 // 5700
	IopRSqrtStep32Fx4             IROp = 0x1645 // 5701
	IopI32UtoFx4                  IROp = 0x1646 // 5702
	IopI32StoFx4                  IROp = 0x1647 // 5703
	IopFtoI32Ux4RZ                IROp = 0x1648 // 5704
	IopFtoI32Sx4RZ                IROp = 0x1649 // 5705
	IopQFtoI32Ux4RZ               IROp = 0x164A // 5706
	IopQFtoI32Sx4RZ               IROp = 0x164B // 5707
	IopRoundF32x4RM               IROp = 0x164C // 5708
	IopRoundF32x4RP               IROp = 0x164D // 5709
	IopRoundF32x4RN               IROp = 0x164E // 5710
	IopRoundF32x4RZ               IROp = 0x164F // 5711
	IopF32ToFixed32Ux4RZ          IROp = 0x1650 // 5712
	IopF32ToFixed32Sx4RZ          IROp = 0x1651 // 5713
	IopFixed32UToF32x4RN          IROp = 0x1652 // 5714
	IopFixed32SToF32x4RN          IROp = 0x1653 // 5715
	IopF32toF16x4                 IROp = 0x1654 // 5716
	IopF16toF32x4                 IROp = 0x1655 // 5717
	IopF64toF16x2                 IROp = 0x1656 // 5718
	IopF16toF64x2                 IROp = 0x1657 // 5719
	IopAdd32F0x4                  IROp = 0x1658 // 5720
	IopSub32F0x4                  IROp = 0x1659 // 5721
	IopMul32F0x4                  IROp = 0x165A // 5722
	IopDiv32F0x4                  IROp = 0x165B // 5723
	IopMax32F0x4                  IROp = 0x165C // 5724
	IopMin32F0x4                  IROp = 0x165D // 5725
	IopCmpEQ32F0x4                IROp = 0x165E // 5726
	IopCmpLT32F0x4                IROp = 0x165F // 5727
	IopCmpLE32F0x4                IROp = 0x1660 // 5728
	IopCmpUN32F0x4                IROp = 0x1661 // 5729
	IopRecipEst32F0x4             IROp = 0x1662 // 5730
	IopSqrt32F0x4                 IROp = 0x1663 // 5731
	IopRSqrtEst32F0x4             IROp = 0x1664 // 5732
	IopAdd64Fx2                   IROp = 0x1665 // 5733
	IopSub64Fx2                   IROp = 0x1666 // 5734
	IopMul64Fx2                   IROp = 0x1667 // 5735
	IopDiv64Fx2                   IROp = 0x1668 // 5736
	IopMax64Fx2                   IROp = 0x1669 // 5737
	IopMin64Fx2                   IROp = 0x166A // 5738
	IopCmpEQ64Fx2                 IROp = 0x166B // 5739
	IopCmpLT64Fx2                 IROp = 0x166C // 5740
	IopCmpLE64Fx2                 IROp = 0x166D // 5741
	IopCmpUN64Fx2                 IROp = 0x166E // 5742
	IopAbs64Fx2                   IROp = 0x166F // 5743
	IopNeg64Fx2                   IROp = 0x1670 // 5744
	IopSqrt64Fx2                  IROp = 0x1671 // 5745
	IopRecipEst64Fx2              IROp = 0x1672 // unary
	IopRecipStep64Fx2             IROp = 0x1673 // binary
	IopRSqrtEst64Fx2              IROp = 0x1674 // unary
	IopRSqrtStep64Fx2             IROp = 0x1675 // binary
	IopAdd64F0x2                  IROp = 0x1676 // 5750
	IopSub64F0x2                  IROp = 0x1677 // 5751
	IopMul64F0x2                  IROp = 0x1678 // 5752
	IopDiv64F0x2                  IROp = 0x1679 // 5753
	IopMax64F0x2                  IROp = 0x167A // 5754
	IopMin64F0x2                  IROp = 0x167B // 5755
	IopCmpEQ64F0x2                IROp = 0x167C // 5756
	IopCmpLT64F0x2                IROp = 0x167D // 5757
	IopCmpLE64F0x2                IROp = 0x167E // 5758
	IopCmpUN64F0x2                IROp = 0x167F // 5759
	IopSqrt64F0x2                 IROp = 0x1680 // 5760
	IopV128to64                   IROp = 0x1681 // :: V128 -> I64, low half
	IopV128HIto64                 IROp = 0x1682 // :: V128 -> I64, high half
	Iop64HLtoV128                 IROp = 0x1683 // :: (I64,I64) -> V128
	Iop64UtoV128                  IROp = 0x1684 // 5764
	IopSetV128lo64                IROp = 0x1685 // 5765
	IopZeroHI64ofV128             IROp = 0x1686 // :: V128 -> V128
	IopZeroHI96ofV128             IROp = 0x1687 // :: V128 -> V128
	IopZeroHI112ofV128            IROp = 0x1688 // :: V128 -> V128
	IopZeroHI120ofV128            IROp = 0x1689 // :: V128 -> V128
	Iop32UtoV128                  IROp = 0x168A // 5770
	IopV128to32                   IROp = 0x168B // :: V128 -> I32, lowest lane
	IopSetV128lo32                IROp = 0x168C // :: (V128,I32) -> V128
	IopNotV128                    IROp = 0x168D // 5773
	IopAndV128                    IROp = 0x168E // 5774
	IopOrV128                     IROp = 0x168F // 5775
	IopXorV128                    IROp = 0x1690 // 5776
	IopShlV128                    IROp = 0x1691 // 5777
	IopShrV128                    IROp = 0x1692 // 5778
	IopSarV128                    IROp = 0x1693 // 5779
	IopCmpNEZ8x16                 IROp = 0x1694 // 5780
	IopCmpNEZ16x8                 IROp = 0x1695 // 5781
	IopCmpNEZ32x4                 IROp = 0x1696 // 5782
	IopCmpNEZ64x2                 IROp = 0x1697 // 5783
	IopCmpNEZ128x1                IROp = 0x1698 // 5784
	IopAdd8x16                    IROp = 0x1699 // 5785
	IopAdd16x8                    IROp = 0x169A // 5786
	IopAdd32x4                    IROp = 0x169B // 5787
	IopAdd64x2                    IROp = 0x169C // 5788
	IopAdd128x1                   IROp = 0x169D // 5789
	IopQAdd8Ux16                  IROp = 0x169E // 5790
	IopQAdd16Ux8                  IROp = 0x169F // 5791
	IopQAdd32Ux4                  IROp = 0x16A0 // 5792
	IopQAdd64Ux2                  IROp = 0x16A1 // 5793
	IopQAdd8Sx16                  IROp = 0x16A2 // 5794
	IopQAdd16Sx8                  IROp = 0x16A3 // 5795
	IopQAdd32Sx4                  IROp = 0x16A4 // 5796
	IopQAdd64Sx2                  IROp = 0x16A5 // 5797
	IopQAddExtUSsatSS8x16         IROp = 0x16A6 // 5798
	IopQAddExtUSsatSS16x8         IROp = 0x16A7 // 5799
	IopQAddExtUSsatSS32x4         IROp = 0x16A8 // 5800
	IopQAddExtUSsatSS64x2         IROp = 0x16A9 // 5801
	IopQAddExtSUsatUU8x16         IROp = 0x16AA // 5802
	IopQAddExtSUsatUU16x8         IROp = 0x16AB // 5803
	IopQAddExtSUsatUU32x4         IROp = 0x16AC // 5804
	IopQAddExtSUsatUU64x2         IROp = 0x16AD // 5805
	IopSub8x16                    IROp = 0x16AE // 5806
	IopSub16x8                    IROp = 0x16AF // 5807
	IopSub32x4                    IROp = 0x16B0 // 5808
	IopSub64x2                    IROp = 0x16B1 // 5809
	IopSub128x1                   IROp = 0x16B2 // 5810
	IopQSub8Ux16                  IROp = 0x16B3 // 5811
	IopQSub16Ux8                  IROp = 0x16B4 // 5812
	IopQSub32Ux4                  IROp = 0x16B5 // 5813
	IopQSub64Ux2                  IROp = 0x16B6 // 5814
	IopQSub8Sx16                  IROp = 0x16B7 // 5815
	IopQSub16Sx8                  IROp = 0x16B8 // 5816
	IopQSub32Sx4                  IROp = 0x16B9 // 5817
	IopQSub64Sx2                  IROp = 0x16BA // 5818
	IopMul8x16                    IROp = 0x16BB // 5819
	IopMul16x8                    IROp = 0x16BC // 5820
	IopMul32x4                    IROp = 0x16BD // 5821
	IopMulHi8Ux16                 IROp = 0x16BE // 5822
	IopMulHi16Ux8                 IROp = 0x16BF // 5823
	IopMulHi32Ux4                 IROp = 0x16C0 // 5824
	IopMulHi8Sx16                 IROp = 0x16C1 // 5825
	IopMulHi16Sx8                 IROp = 0x16C2 // 5826
	IopMulHi32Sx4                 IROp = 0x16C3 // 5827
	IopMullEven8Ux16              IROp = 0x16C4 // 5828
	IopMullEven16Ux8              IROp = 0x16C5 // 5829
	IopMullEven32Ux4              IROp = 0x16C6 // 5830
	IopMullEven8Sx16              IROp = 0x16C7 // 5831
	IopMullEven16Sx8              IROp = 0x16C8 // 5832
	IopMullEven32Sx4              IROp = 0x16C9 // 5833
	IopMull8Ux8                   IROp = 0x16CA // 5834
	IopMull8Sx8                   IROp = 0x16CB // 5835
	IopMull16Ux4                  IROp = 0x16CC // 5836
	IopMull16Sx4                  IROp = 0x16CD // 5837
	IopMull32Ux2                  IROp = 0x16CE // 5838
	IopMull32Sx2                  IROp = 0x16CF // 5839
	IopQDMull16Sx4                IROp = 0x16D0 // 5840
	IopQDMull32Sx2                IROp = 0x16D1 // 5841
	IopQDMulHi16Sx8               IROp = 0x16D2 // 5842
	IopQDMulHi32Sx4               IROp = 0x16D3 // 5843
	IopQRDMulHi16Sx8              IROp = 0x16D4 // 5844
	IopQRDMulHi32Sx4              IROp = 0x16D5 // 5845
	IopPolynomialMul8x16          IROp = 0x16D6 // 5846
	IopPolynomialMull8x8          IROp = 0x16D7 // 5847
	IopPolynomialMulAdd8x16       IROp = 0x16D8 // 5848
	IopPolynomialMulAdd16x8       IROp = 0x16D9 // 5849
	IopPolynomialMulAdd32x4       IROp = 0x16DA // 5850
	IopPolynomialMulAdd64x2       IROp = 0x16DB // 5851
	IopPwAdd8x16                  IROp = 0x16DC // 5852
	IopPwAdd16x8                  IROp = 0x16DD // 5853
	IopPwAdd32x4                  IROp = 0x16DE // 5854
	IopPwAdd32Fx2                 IROp = 0x16DF // 5855
	IopPwAddL8Ux16                IROp = 0x16E0 // 5856
	IopPwAddL16Ux8                IROp = 0x16E1 // 5857
	IopPwAddL32Ux4                IROp = 0x16E2 // 5858
	IopPwAddL64Ux2                IROp = 0x16E3 // 5859
	IopPwAddL8Sx16                IROp = 0x16E4 // 5860
	IopPwAddL16Sx8                IROp = 0x16E5 // 5861
	IopPwAddL32Sx4                IROp = 0x16E6 // 5862
	IopPwBitMtxXpose64x2          IROp = 0x16E7 // 5863
	IopAbs8x16                    IROp = 0x16E8 // 5864
	IopAbs16x8                    IROp = 0x16E9 // 5865
	IopAbs32x4                    IROp = 0x16EA // 5866
	IopAbs64x2                    IROp = 0x16EB // 5867
	IopAvg8Ux16                   IROp = 0x16EC // 5868
	IopAvg16Ux8                   IROp = 0x16ED // 5869
	IopAvg32Ux4                   IROp = 0x16EE // 5870
	IopAvg64Ux2                   IROp = 0x16EF // 5871
	IopAvg8Sx16                   IROp = 0x16F0 // 5872
	IopAvg16Sx8                   IROp = 0x16F1 // 5873
	IopAvg32Sx4                   IROp = 0x16F2 // 5874
	IopAvg64Sx2                   IROp = 0x16F3 // 5875
	IopMax8Sx16                   IROp = 0x16F4 // 5876
	IopMax16Sx8                   IROp = 0x16F5 // 5877
	IopMax32Sx4                   IROp = 0x16F6 // 5878
	IopMax64Sx2                   IROp = 0x16F7 // 5879
	IopMax8Ux16                   IROp = 0x16F8 // 5880
	IopMax16Ux8                   IROp = 0x16F9 // 5881
	IopMax32Ux4                   IROp = 0x16FA // 5882
	IopMax64Ux2                   IROp = 0x16FB // 5883
	IopMin8Sx16                   IROp = 0x16FC // 5884
	IopMin16Sx8                   IROp = 0x16FD // 5885
	IopMin32Sx4                   IROp = 0x16FE // 5886
	IopMin64Sx2                   IROp = 0x16FF // 5887
	IopMin8Ux16                   IROp = 0x1700 // 5888
	IopMin16Ux8                   IROp = 0x1701 // 5889
	IopMin32Ux4                   IROp = 0x1702 // 5890
	IopMin64Ux2                   IROp = 0x1703 // 5891
	IopCmpEQ8x16                  IROp = 0x1704 // 5892
	IopCmpEQ16x8                  IROp = 0x1705 // 5893
	IopCmpEQ32x4                  IROp = 0x1706 // 5894
	IopCmpEQ64x2                  IROp = 0x1707 // 5895
	IopCmpGT8Sx16                 IROp = 0x1708 // 5896
	IopCmpGT16Sx8                 IROp = 0x1709 // 5897
	IopCmpGT32Sx4                 IROp = 0x170A // 5898
	IopCmpGT64Sx2                 IROp = 0x170B // 5899
	IopCmpGT8Ux16                 IROp = 0x170C // 5900
	IopCmpGT16Ux8                 IROp = 0x170D // 5901
	IopCmpGT32Ux4                 IROp = 0x170E // 5902
	IopCmpGT64Ux2                 IROp = 0x170F // 5903
	IopCnt8x16                    IROp = 0x1710 // 5904
	IopClz8x16                    IROp = 0x1711 // 5905
	IopClz16x8                    IROp = 0x1712 // 5906
	IopClz32x4                    IROp = 0x1713 // 5907
	IopCls8x16                    IROp = 0x1714 // 5908
	IopCls16x8                    IROp = 0x1715 // 5909
	IopCls32x4                    IROp = 0x1716 // 5910
	IopShlN8x16                   IROp = 0x1717 // 5911
	IopShlN16x8                   IROp = 0x1718 // 5912
	IopShlN32x4                   IROp = 0x1719 // 5913
	IopShlN64x2                   IROp = 0x171A // 5914
	IopShrN8x16                   IROp = 0x171B // 5915
	IopShrN16x8                   IROp = 0x171C // 5916
	IopShrN32x4                   IROp = 0x171D // 5917
	IopShrN64x2                   IROp = 0x171E // 5918
	IopSarN8x16                   IROp = 0x171F // 5919
	IopSarN16x8                   IROp = 0x1720 // 5920
	IopSarN32x4                   IROp = 0x1721 // 5921
	IopSarN64x2                   IROp = 0x1722 // 5922
	IopShl8x16                    IROp = 0x1723 // 5923
	IopShl16x8                    IROp = 0x1724 // 5924
	IopShl32x4                    IROp = 0x1725 // 5925
	IopShl64x2                    IROp = 0x1726 // 5926
	IopShr8x16                    IROp = 0x1727 // 5927
	IopShr16x8                    IROp = 0x1728 // 5928
	IopShr32x4                    IROp = 0x1729 // 5929
	IopShr64x2                    IROp = 0x172A // 5930
	IopSar8x16                    IROp = 0x172B // 5931
	IopSar16x8                    IROp = 0x172C // 5932
	IopSar32x4                    IROp = 0x172D // 5933
	IopSar64x2                    IROp = 0x172E // 5934
	IopSal8x16                    IROp = 0x172F // 5935
	IopSal16x8                    IROp = 0x1730 // 5936
	IopSal32x4                    IROp = 0x1731 // 5937
	IopSal64x2                    IROp = 0x1732 // 5938
	IopRol8x16                    IROp = 0x1733 // 5939
	IopRol16x8                    IROp = 0x1734 // 5940
	IopRol32x4                    IROp = 0x1735 // 5941
	IopRol64x2                    IROp = 0x1736 // 5942
	IopQShl8x16                   IROp = 0x1737 // 5943
	IopQShl16x8                   IROp = 0x1738 // 5944
	IopQShl32x4                   IROp = 0x1739 // 5945
	IopQShl64x2                   IROp = 0x173A // 5946
	IopQSal8x16                   IROp = 0x173B // 5947
	IopQSal16x8                   IROp = 0x173C // 5948
	IopQSal32x4                   IROp = 0x173D // 5949
	IopQSal64x2                   IROp = 0x173E // 5950
	IopQShlNsatSU8x16             IROp = 0x173F // 5951
	IopQShlNsatSU16x8             IROp = 0x1740 // 5952
	IopQShlNsatSU32x4             IROp = 0x1741 // 5953
	IopQShlNsatSU64x2             IROp = 0x1742 // 5954
	IopQShlNsatUU8x16             IROp = 0x1743 // 5955
	IopQShlNsatUU16x8             IROp = 0x1744 // 5956
	IopQShlNsatUU32x4             IROp = 0x1745 // 5957
	IopQShlNsatUU64x2             IROp = 0x1746 // 5958
	IopQShlNsatSS8x16             IROp = 0x1747 // 5959
	IopQShlNsatSS16x8             IROp = 0x1748 // 5960
	IopQShlNsatSS32x4             IROp = 0x1749 // 5961
	IopQShlNsatSS64x2             IROp = 0x174A // 5962
	IopQandUQsh8x16               IROp = 0x174B // 5963
	IopQandUQsh16x8               IROp = 0x174C // 5964
	IopQandUQsh32x4               IROp = 0x174D // 5965
	IopQandUQsh64x2               IROp = 0x174E // 5966
	IopQandSQsh8x16               IROp = 0x174F // 5967
	IopQandSQsh16x8               IROp = 0x1750 // 5968
	IopQandSQsh32x4               IROp = 0x1751 // 5969
	IopQandSQsh64x2               IROp = 0x1752 // 5970
	IopQandUQRsh8x16              IROp = 0x1753 // 5971
	IopQandUQRsh16x8              IROp = 0x1754 // 5972
	IopQandUQRsh32x4              IROp = 0x1755 // 5973
	IopQandUQRsh64x2              IROp = 0x1756 // 5974
	IopQandSQRsh8x16              IROp = 0x1757 // 5975
	IopQandSQRsh16x8              IROp = 0x1758 // 5976
	IopQandSQRsh32x4              IROp = 0x1759 // 5977
	IopQandSQRsh64x2              IROp = 0x175A // 5978
	IopSh8Sx16                    IROp = 0x175B // 5979
	IopSh16Sx8                    IROp = 0x175C // 5980
	IopSh32Sx4                    IROp = 0x175D // 5981
	IopSh64Sx2                    IROp = 0x175E // 5982
	IopSh8Ux16                    IROp = 0x175F // 5983
	IopSh16Ux8                    IROp = 0x1760 // 5984
	IopSh32Ux4                    IROp = 0x1761 // 5985
	IopSh64Ux2                    IROp = 0x1762 // 5986
	IopRsh8Sx16                   IROp = 0x1763 // 5987
	IopRsh16Sx8                   IROp = 0x1764 // 5988
	IopRsh32Sx4                   IROp = 0x1765 // 5989
	IopRsh64Sx2                   IROp = 0x1766 // 5990
	IopRsh8Ux16                   IROp = 0x1767 // 5991
	IopRsh16Ux8                   IROp = 0x1768 // 5992
	IopRsh32Ux4                   IROp = 0x1769 // 5993
	IopRsh64Ux2                   IROp = 0x176A // 5994
	IopQandQShrNnarrow16Uto8Ux8   IROp = 0x176B // 5995
	IopQandQShrNnarrow32Uto16Ux4  IROp = 0x176C // 5996
	IopQandQShrNnarrow64Uto32Ux2  IROp = 0x176D // 5997
	IopQandQSarNnarrow16Sto8Sx8   IROp = 0x176E // 5998
	IopQandQSarNnarrow32Sto16Sx4  IROp = 0x176F // 5999
	IopQandQSarNnarrow64Sto32Sx2  IROp = 0x1770 // 6000
	IopQandQSarNnarrow16Sto8Ux8   IROp = 0x1771 // 6001
	IopQandQSarNnarrow32Sto16Ux4  IROp = 0x1772 // 6002
	IopQandQSarNnarrow64Sto32Ux2  IROp = 0x1773 // 6003
	IopQandQRShrNnarrow16Uto8Ux8  IROp = 0x1774 // 6004
	IopQandQRShrNnarrow32Uto16Ux4 IROp = 0x1775 // 6005
	IopQandQRShrNnarrow64Uto32Ux2 IROp = 0x1776 // 6006
	IopQandQRSarNnarrow16Sto8Sx8  IROp = 0x1777 // 6007
	IopQandQRSarNnarrow32Sto16Sx4 IROp = 0x1778 // 6008
	IopQandQRSarNnarrow64Sto32Sx2 IROp = 0x1779 // 6009
	IopQandQRSarNnarrow16Sto8Ux8  IROp = 0x177A // 6010
	IopQandQRSarNnarrow32Sto16Ux4 IROp = 0x177B // 6011
	IopQandQRSarNnarrow64Sto32Ux2 IROp = 0x177C // 6012
	IopQNarrowBin16Sto8Ux16       IROp = 0x177D // 6013
	IopQNarrowBin32Sto16Ux8       IROp = 0x177E // 6014
	IopQNarrowBin16Sto8Sx16       IROp = 0x177F // 6015
	IopQNarrowBin32Sto16Sx8       IROp = 0x1780 // 6016
	IopQNarrowBin16Uto8Ux16       IROp = 0x1781 // 6017
	IopQNarrowBin32Uto16Ux8       IROp = 0x1782 // 6018
	IopNarrowBin16to8x16          IROp = 0x1783 // 6019
	IopNarrowBin32to16x8          IROp = 0x1784 // 6020
	IopQNarrowBin64Sto32Sx4       IROp = 0x1785 // 6021
	IopQNarrowBin64Uto32Ux4       IROp = 0x1786 // 6022
	IopNarrowBin64to32x4          IROp = 0x1787 // 6023
	IopNarrowUn16to8x8            IROp = 0x1788 // 6024
	IopNarrowUn32to16x4           IROp = 0x1789 // 6025
	IopNarrowUn64to32x2           IROp = 0x178A // 6026
	IopQNarrowUn16Sto8Sx8         IROp = 0x178B // 6027
	IopQNarrowUn32Sto16Sx4        IROp = 0x178C // 6028
	IopQNarrowUn64Sto32Sx2        IROp = 0x178D // 6029
	IopQNarrowUn16Sto8Ux8         IROp = 0x178E // 6030
	IopQNarrowUn32Sto16Ux4        IROp = 0x178F // 6031
	IopQNarrowUn64Sto32Ux2        IROp = 0x1790 // 6032
	IopQNarrowUn16Uto8Ux8         IROp = 0x1791 // 6033
	IopQNarrowUn32Uto16Ux4        IROp = 0x1792 // 6034
	IopQNarrowUn64Uto32Ux2        IROp = 0x1793 // 6035
	IopWiden8Uto16x8              IROp = 0x1794 // 6036
	IopWiden16Uto32x4             IROp = 0x1795 // 6037
	IopWiden32Uto64x2             IROp = 0x1796 // 6038
	IopWiden8Sto16x8              IROp = 0x1797 // 6039
	IopWiden16Sto32x4             IROp = 0x1798 // 6040
	IopWiden32Sto64x2             IROp = 0x1799 // 6041
	IopInterleaveHI8x16           IROp = 0x179A // 6042
	IopInterleaveHI16x8           IROp = 0x179B // 6043
	IopInterleaveHI32x4           IROp = 0x179C // 6044
	IopInterleaveHI64x2           IROp = 0x179D // 6045
	IopInterleaveLO8x16           IROp = 0x179E // 6046
	IopInterleaveLO16x8           IROp = 0x179F // 6047
	IopInterleaveLO32x4           IROp = 0x17A0 // 6048
	IopInterleaveLO64x2           IROp = 0x17A1 // 6049
	IopInterleaveOddLanes8x16     IROp = 0x17A2 // 6050
	IopInterleaveEvenLanes8x16    IROp = 0x17A3 // 6051
	IopInterleaveOddLanes16x8     IROp = 0x17A4 // 6052
	IopInterleaveEvenLanes16x8    IROp = 0x17A5 // 6053
	IopInterleaveOddLanes32x4     IROp = 0x17A6 // 6054
	IopInterleaveEvenLanes32x4    IROp = 0x17A7 // 6055
	IopCatOddLanes8x16            IROp = 0x17A8 // 6056
	IopCatOddLanes16x8            IROp = 0x17A9 // 6057
	IopCatOddLanes32x4            IROp = 0x17AA // 6058
	IopCatEvenLanes8x16           IROp = 0x17AB // 6059
	IopCatEvenLanes16x8           IROp = 0x17AC // 6060
	IopCatEvenLanes32x4           IROp = 0x17AD // 6061
	IopGetElem8x16                IROp = 0x17AE // 6062
	IopGetElem16x8                IROp = 0x17AF // 6063
	IopGetElem32x4                IROp = 0x17B0 // 6064
	IopGetElem64x2                IROp = 0x17B1 // 6065
	IopSetElem8x16                IROp = 0x17B2 // 6066
	IopSetElem16x8                IROp = 0x17B3 // 6067
	IopSetElem32x4                IROp = 0x17B4 // 6068
	IopSetElem64x2                IROp = 0x17B5 // 6069
	IopDup8x16                    IROp = 0x17B6 // 6070
	IopDup16x8                    IROp = 0x17B7 // 6071
	IopDup32x4                    IROp = 0x17B8 // 6072
	IopSliceV128                  IROp = 0x17B9 // (V128, V128, I8) -> V128
	IopReverse8sIn16x8            IROp = 0x17BA // 6074
	IopReverse8sIn32x4            IROp = 0x17BB // 6075
	IopReverse16sIn32x4           IROp = 0x17BC // 6076
	IopReverse8sIn64x2            IROp = 0x17BD // 6077
	IopReverse16sIn64x2           IROp = 0x17BE // 6078
	IopReverse32sIn64x2           IROp = 0x17BF // 6079
	IopReverse1sIn8x16            IROp = 0x17C0 // 6080
	IopPerm8x16                   IROp = 0x17C1 // 6081
	IopPerm32x4                   IROp = 0x17C2 // 6082
	IopPerm8x16x2                 IROp = 0x17C3 // 6083
	IopGetMSBs8x16                IROp = 0x17C4 // 6084
	IopRecipEst32Ux4              IROp = 0x17C5 // 6085
	IopRSqrtEst32Ux4              IROp = 0x17C6 // 6086
	IopMulI128by10                IROp = 0x17C7 // 6087
	IopMulI128by10Carry           IROp = 0x17C8 // 6088
	IopMulI128by10E               IROp = 0x17C9 // 6089
	IopMulI128by10ECarry          IROp = 0x17CA // 6090
	IopV256to640                  IROp = 0x17CB // V256 -> I64, extract least significant lane
	IopV256to641                  IROp = 0x17CC // 6092
	IopV256to642                  IROp = 0x17CD // 6093
	IopV256to643                  IROp = 0x17CE // V256 -> I64, extract most significant lane
	Iop64x4toV256                 IROp = 0x17CF // (I64,I64,I64,I64)->V256
	IopV256toV1280                IROp = 0x17D0 // V256 -> V128, less significant lane
	IopV256toV1281                IROp = 0x17D1 // V256 -> V128, more significant lane
	IopV128HLtoV256               IROp = 0x17D2 // (V128,V128)->V256, first arg is most signif
	IopAndV256                    IROp = 0x17D3 // 6099
	IopOrV256                     IROp = 0x17D4 // 6100
	IopXorV256                    IROp = 0x17D5 // 6101
	IopNotV256                    IROp = 0x17D6 // 6102
	IopCmpNEZ8x32                 IROp = 0x17D7 // 6103
	IopCmpNEZ16x16                IROp = 0x17D8 // 6104
	IopCmpNEZ32x8                 IROp = 0x17D9 // 6105
	IopCmpNEZ64x4                 IROp = 0x17DA // 6106
	IopAdd8x32                    IROp = 0x17DB // 6107
	IopAdd16x16                   IROp = 0x17DC // 6108
	IopAdd32x8                    IROp = 0x17DD // 6109
	IopAdd64x4                    IROp = 0x17DE // 6110
	IopSub8x32                    IROp = 0x17DF // 6111
	IopSub16x16                   IROp = 0x17E0 // 6112
	IopSub32x8                    IROp = 0x17E1 // 6113
	IopSub64x4                    IROp = 0x17E2 // 6114
	IopCmpEQ8x32                  IROp = 0x17E3 // 6115
	IopCmpEQ16x16                 IROp = 0x17E4 // 6116
	IopCmpEQ32x8                  IROp = 0x17E5 // 6117
	IopCmpEQ64x4                  IROp = 0x17E6 // 6118
	IopCmpGT8Sx32                 IROp = 0x17E7 // 6119
	IopCmpGT16Sx16                IROp = 0x17E8 // 6120
	IopCmpGT32Sx8                 IROp = 0x17E9 // 6121
	IopCmpGT64Sx4                 IROp = 0x17EA // 6122
	IopShlN16x16                  IROp = 0x17EB // 6123
	IopShlN32x8                   IROp = 0x17EC // 6124
	IopShlN64x4                   IROp = 0x17ED // 6125
	IopShrN16x16                  IROp = 0x17EE // 6126
	IopShrN32x8                   IROp = 0x17EF // 6127
	IopShrN64x4                   IROp = 0x17F0 // 6128
	IopSarN16x16                  IROp = 0x17F1 // 6129
	IopSarN32x8                   IROp = 0x17F2 // 6130
	IopMax8Sx32                   IROp = 0x17F3 // 6131
	IopMax16Sx16                  IROp = 0x17F4 // 6132
	IopMax32Sx8                   IROp = 0x17F5 // 6133
	IopMax8Ux32                   IROp = 0x17F6 // 6134
	IopMax16Ux16                  IROp = 0x17F7 // 6135
	IopMax32Ux8                   IROp = 0x17F8 // 6136
	IopMin8Sx32                   IROp = 0x17F9 // 6137
	IopMin16Sx16                  IROp = 0x17FA // 6138
	IopMin32Sx8                   IROp = 0x17FB // 6139
	IopMin8Ux32                   IROp = 0x17FC // 6140
	IopMin16Ux16                  IROp = 0x17FD // 6141
	IopMin32Ux8                   IROp = 0x17FE // 6142
	IopMul16x16                   IROp = 0x17FF // 6143
	IopMul32x8                    IROp = 0x1800 // 6144
	IopMulHi16Ux16                IROp = 0x1801 // 6145
	IopMulHi16Sx16                IROp = 0x1802 // 6146
	IopQAdd8Ux32                  IROp = 0x1803 // 6147
	IopQAdd16Ux16                 IROp = 0x1804 // 6148
	IopQAdd8Sx32                  IROp = 0x1805 // 6149
	IopQAdd16Sx16                 IROp = 0x1806 // 6150
	IopQSub8Ux32                  IROp = 0x1807 // 6151
	IopQSub16Ux16                 IROp = 0x1808 // 6152
	IopQSub8Sx32                  IROp = 0x1809 // 6153
	IopQSub16Sx16                 IROp = 0x180A // 6154
	IopAvg8Ux32                   IROp = 0x180B // 6155
	IopAvg16Ux16                  IROp = 0x180C // 6156
	IopPerm32x8                   IROp = 0x180D // 6157
	IopCipherV128                 IROp = 0x180E // 6158
	IopCipherLV128                IROp = 0x180F // 6159
	IopCipherSV128                IROp = 0x1810 // 6160
	IopNCipherV128                IROp = 0x1811 // 6161
	IopNCipherLV128               IROp = 0x1812 // 6162
	IopSHA512                     IROp = 0x1813 // 6163
	IopSHA256                     IROp = 0x1814 // 6164
	IopAdd64Fx4                   IROp = 0x1815 // 6165
	IopSub64Fx4                   IROp = 0x1816 // 6166
	IopMul64Fx4                   IROp = 0x1817 // 6167
	IopDiv64Fx4                   IROp = 0x1818 // 6168
	IopAdd32Fx8                   IROp = 0x1819 // 6169
	IopSub32Fx8                   IROp = 0x181A // 6170
	IopMul32Fx8                   IROp = 0x181B // 6171
	IopDiv32Fx8                   IROp = 0x181C // 6172
	IopSqrt32Fx8                  IROp = 0x181D // 6173
	IopSqrt64Fx4                  IROp = 0x181E // 6174
	IopRSqrtEst32Fx8              IROp = 0x181F // 6175
	IopRecipEst32Fx8              IROp = 0x1820 // 6176
	IopMax32Fx8                   IROp = 0x1821 // 6177
	IopMin32Fx8                   IROp = 0x1822 // 6178
	IopMax64Fx4                   IROp = 0x1823 // 6179
	IopMin64Fx4                   IROp = 0x1824 // 6180
	IopLAST                       IROp = 0x1825 // 6181
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
