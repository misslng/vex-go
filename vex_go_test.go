package vex_go

import (
	"fmt"
	"testing"
)

func TestVexInit(t *testing.T) {
	VexInit()
	mc := []byte{0xe2, 0x03, 0x00, 0xaa}
	liftR := VexLift(VexArchARM64, mc, 0x1000)

	for i := 0; i < int(liftR.irsb.stmts_used); i++ {
		stmt := GetStmtAt(liftR.irsb.stmts, i, int(liftR.irsb.stmts_size))
		if stmt.tag == Ist_WrTmp {
			wrTmp := stmt.AsWrTmp()
			get := wrTmp.data.AsGet()
			fmt.Println(get.ty)
		}
	}
}
