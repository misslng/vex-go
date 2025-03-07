package vex_go

import (
	"fmt"
	"testing"
)

func TestVexInit(t *testing.T) {
	VexInit()
	mc := []byte{0xe2, 0x03, 0x00, 0xaa}
	liftR := VexLift(VexArchARM64, mc, 0x1000, VexEndnessLE)
	fmt.Println(liftR.TyEnv)
	for i := 0; i < int(liftR.StmtsUsed); i++ {
		stmt := liftR.GetStmt(i)
		switch stmt.Tag {
		case IstIMark:
			fmt.Println(stmt.AsIMark())
		case IstWrTmp:
			wrTmp := stmt.AsWrTmp()
			switch wrTmp.Data.Tag {
			case IexGet:
				get := wrTmp.Data.AsGet()
				fmt.Println(get.Ty)
				//fmt.Println(get.Offset)
			}
		case IstPut:
			put := stmt.AsPut()
			fmt.Println(put.Offset)
			tmp := put.Data.AsRdTmp()
			fmt.Println(tmp.Tmp)
		default:
			fmt.Println(stmt.Tag)
		}
	}
}
