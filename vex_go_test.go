package vex_go

import (
	"fmt"
	"testing"
)

func TestVexInit(t *testing.T) {
	VexInit()
	mc := []byte{0xe2, 0x03, 0x00, 0xaa}
	liftR := VexLift(VexArchARM64, mc, 0x1000)
	for i := 0; i < int(liftR.StmtsUsed); i++ {
		stmt := liftR.GetStmt(i)
		switch stmt.Tag {
		case IstWrTmp:
			wrTmp := stmt.AsWrTmp()
			switch wrTmp.Data.Tag {
			case IexGet:
				fmt.Println(wrTmp.Data.AsGet())
			}
		}
	}
}
