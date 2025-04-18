#include <libvex.h>
#include <stddef.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <libvex_guest_arm.h>
#include <libvex_guest_mips32.h>

#include "pyvex.h"

const int _endian = 0xfe;
#define BE_HOST (*((unsigned char*)&_endian) == 0)
#define LE_HOST (*((unsigned char*)&_endian) != 0)


void remove_noops(
	IRSB* irsb
	) {
	Int noops = 0, i;
	Int pos = 0;

	for (i = 0; i < irsb->stmts_used; ++i) {
		if (irsb->stmts[i]->tag != Ist_NoOp) {
			if (i != pos) {
				irsb->stmts[pos] = irsb->stmts[i];
			}
			pos++;
		}
		else {
			noops++;
		}
	}

	irsb->stmts_used -= noops;
}


void get_exits_and_inst_addrs(
		IRSB *irsb,
		VEXLiftResult *lift_r) {
	Int i, exit_ctr = 0, inst_count = 0;
	Addr ins_addr = -1;
	UInt size = 0;
	for (i = 0; i < irsb->stmts_used; ++i) {
		IRStmt* stmt = irsb->stmts[i];
		if (stmt->tag == Ist_Exit) {
			assert(ins_addr != -1);
			if (exit_ctr < MAX_EXITS) {
				lift_r->exits[exit_ctr].ins_addr = ins_addr;
				lift_r->exits[exit_ctr].stmt_idx = i;
				lift_r->exits[exit_ctr].stmt = stmt;
			}
			exit_ctr += 1;
		}
		else if (stmt->tag == Ist_IMark) {
			ins_addr = stmt->Ist.IMark.addr + stmt->Ist.IMark.delta;
			size += stmt->Ist.IMark.len;
			if (inst_count < sizeof(lift_r->inst_addrs) / sizeof(Addr)) {
				lift_r->inst_addrs[inst_count] = ins_addr;
			}
			// inst_count is incremented anyway. If lift_r->insts > 200, the overflowed
			// instruction addresses will not be written into inst_addrs.
			inst_count++;
		}
	}

	lift_r->exit_count = exit_ctr;
	lift_r->size = size;
	lift_r->insts = inst_count;
}

void get_default_exit_target(
		IRSB *irsb,
		VEXLiftResult *lift_r ) {

	IRTemp tmp;
	Int reg = -1;
	IRType reg_type = Ity_INVALID;
	Int i;

	lift_r->is_default_exit_constant = 0;

	if (irsb->jumpkind != Ijk_InvalICache && irsb->jumpkind != Ijk_Boring && irsb->jumpkind != Ijk_Call) {
		return;
	}

	if (irsb->next->tag == Iex_Const) {
		IRConst *con = irsb->next->Iex.Const.con;
		switch (con->tag) {
		case Ico_U16:
			lift_r->is_default_exit_constant = 1;
			lift_r->default_exit = con->Ico.U16;
			break;
		case Ico_U32:
			lift_r->is_default_exit_constant = 1;
			lift_r->default_exit = con->Ico.U32;
			break;
		case Ico_U64:
			lift_r->is_default_exit_constant = 1;
			lift_r->default_exit = con->Ico.U64;
			break;
		default:
			// A weird address... we don't support it.
			break;
		}
		return;
	}

	if (irsb->next->tag != Iex_RdTmp) {
		// Unexpected irsb->next type
		return;
	}

	// Scan statements backwards to find the assigning statement
	tmp = irsb->next->Iex.RdTmp.tmp;
	for (i = irsb->stmts_used - 1; i >= 0; --i) {
		IRExpr *data = NULL;
		IRStmt *stmt = irsb->stmts[i];
		if (stmt->tag == Ist_WrTmp &&
				stmt->Ist.WrTmp.tmp == tmp) {
			data = stmt->Ist.WrTmp.data;
		}
		else if (stmt->tag == Ist_Put &&
				stmt->Ist.Put.offset == reg) {
			IRType put_type = typeOfIRExpr(irsb->tyenv, stmt->Ist.Put.data);
			if (put_type != reg_type) {
				// The size does not match. Give up.
				return;
			}
			data = stmt->Ist.Put.data;
		}
		else if (stmt->tag == Ist_LoadG) {
			// We do not handle LoadG. Give up.
			return;
		}
		else {
			continue;
		}

		if (data->tag == Iex_Const) {
			lift_r->is_default_exit_constant = 1;
			IRConst *con = data->Iex.Const.con;
			switch (con->tag) {
			case Ico_U16:
				lift_r->is_default_exit_constant = 1;
				lift_r->default_exit = con->Ico.U16;
				break;
			case Ico_U32:
				lift_r->is_default_exit_constant = 1;
				lift_r->default_exit = con->Ico.U32;
				break;
			case Ico_U64:
				lift_r->is_default_exit_constant = 1;
				lift_r->default_exit = con->Ico.U64;
				break;
			default:
				// A weird address... we don't support it.
				break;
			}
			return;
		}
		else if (data->tag == Iex_RdTmp) {
			// Reading another temp variable
			tmp = data->Iex.RdTmp.tmp;
			reg = -1;
		}
		else if (data->tag == Iex_Get) {
			// Reading from a register
			tmp = IRTemp_INVALID;
			reg = data->Iex.Get.offset;
			reg_type = typeOfIRExpr(irsb->tyenv, data);
		}
		else {
			// Something we don't currently support
			return;
		}
	}

	// We cannot resolve it to a constant value.
	return;
}


Addr get_value_from_const_expr(
	IRConst* con) {

	switch (con->tag) {
	case Ico_U8:
		return con->Ico.U8;
	case Ico_U16:
		return con->Ico.U16;
	case Ico_U32:
		return con->Ico.U32;
	case Ico_U64:
		return con->Ico.U64;
	default:
		// A weird address...
		return 0;
	}
}

//
// Collect data references
//


/* General map. Shamelessly stolen from ir_opt.c in libVEX */

typedef
   struct {
      Bool*  inuse;
      HWord* key;
      HWord* val;
      Int    size;
      Int    used;
   }
   HashHW;

static HashHW* newHHW()
{
   HashHW* h = malloc(sizeof(HashHW));
   h->size   = 8;
   h->used   = 0;
   h->inuse  = (Bool*)malloc(h->size * sizeof(Bool));
   h->key    = (HWord*)malloc(h->size * sizeof(HWord));
   h->val    = (HWord*)malloc(h->size * sizeof(HWord));
   return h;
}

static void freeHHW(HashHW* h)
{
	free(h->inuse);
	free(h->key);
	free(h->val);
	free(h);
}


/* Look up key in the map. */

static Bool lookupHHW(HashHW* h, /*OUT*/HWord* val, HWord key)
{
   Int i;

   for (i = 0; i < h->used; i++) {
      if (h->inuse[i] && h->key[i] == key) {
         if (val)
            *val = h->val[i];
         return True;
      }
   }
   return False;
}


/* Add key->val to the map.  Replaces any existing binding for key. */

static void addToHHW(HashHW* h, HWord key, HWord val)
{
   Int i, j;

   /* Find and replace existing binding, if any. */
   for (i = 0; i < h->used; i++) {
      if (h->inuse[i] && h->key[i] == key) {
         h->val[i] = val;
         return;
      }
   }

   /* Ensure a space is available. */
   if (h->used == h->size) {
      /* Copy into arrays twice the size. */
      Bool*  inuse2 = malloc(2 * h->size * sizeof(Bool));
      HWord* key2   = malloc(2 * h->size * sizeof(HWord));
      HWord* val2   = malloc(2 * h->size * sizeof(HWord));
      for (i = j = 0; i < h->size; i++) {
         if (!h->inuse[i]) continue;
         inuse2[j] = True;
         key2[j] = h->key[i];
         val2[j] = h->val[i];
         j++;
      }
      h->used = j;
      h->size *= 2;
	  free(h->inuse);
      h->inuse = inuse2;
	  free(h->key);
      h->key = key2;
	  free(h->val);
      h->val = val2;
   }

   /* Finally, add it. */
   h->inuse[h->used] = True;
   h->key[h->used] = key;
   h->val[h->used] = val;
   h->used++;
}

/* Remove key from the map. */

static void removeFromHHW(HashHW* h, HWord key)
{
   Int i, j;

   /* Find and replace existing binding, if any. */
   for (i = 0; i < h->used; i++) {
      if (h->inuse[i] && h->key[i] == key) {
         h->inuse[i] = False;
         return;
      }
   }
}

/* Create keys, of the form ((minoffset << 16) | maxoffset). */

static UInt mk_key_GetPut ( Int offset, IRType ty )
{
   /* offset should fit in 16 bits. */
   UInt minoff = offset;
   UInt maxoff = minoff + sizeofIRType(ty) - 1;
   return (minoff << 16) | maxoff;
}


void record_data_reference(
	VEXLiftResult *lift_r,
	Addr data_addr,
	Int size,
	DataRefTypes data_type,
	Int stmt_idx,
	Addr inst_addr) {

	if (lift_r->data_ref_count < MAX_DATA_REFS) {
		Int idx = lift_r->data_ref_count;
		lift_r->data_refs[idx].size = size;
		lift_r->data_refs[idx].data_addr = data_addr;
		lift_r->data_refs[idx].data_type = data_type;
		lift_r->data_refs[idx].stmt_idx = stmt_idx;
		lift_r->data_refs[idx].ins_addr = inst_addr;
		lift_r->data_ref_count++;
	}
}

Addr get_const_and_record(
	VEXLiftResult *lift_r,
	IRExpr *const_expr,
	Int size,
	DataRefTypes data_type,
	Int stmt_idx,
	Addr inst_addr,
	Addr next_inst_addr,
	Bool record) {

	if (const_expr->tag != Iex_Const) {
		// Why are you calling me?
		assert (const_expr->tag == Iex_Const);
		return -1;
	}

	Addr addr = get_value_from_const_expr(const_expr->Iex.Const.con);
	if (addr != next_inst_addr) {
		if (record) {
			record_data_reference(lift_r, addr, size, data_type, stmt_idx, inst_addr);
		}
        return addr;
	}
    return -1;
}

void record_tmp_value(
	VEXLiftResult *lift_r,
	Int tmp,
	ULong value,
	Int stmt_idx
) {
	if (lift_r->const_val_count < MAX_CONST_VALS) {
		Int idx = lift_r->const_val_count;
		lift_r->const_vals[idx].tmp = tmp;
		lift_r->const_vals[idx].value = value;
		lift_r->const_vals[idx].stmt_idx = stmt_idx;
		lift_r->const_val_count++;
	}
}


typedef struct {
	int used;
	ULong value;
} TmpValue;


typedef struct {
	Bool in_use;
	ULong start;
	ULong size;
	unsigned char* content;
} Region;

int next_unused_region_id = 0;
#define MAX_REGION_COUNT 1024
Region regions[MAX_REGION_COUNT] = {0};

static int find_region(ULong start)
{
	if (next_unused_region_id > 0 && regions[next_unused_region_id - 1].start < start) {
		if (next_unused_region_id >= MAX_REGION_COUNT) {
			return -1;
		}
		return next_unused_region_id - 1;
	}

	int lo = 0, hi = next_unused_region_id, mid;
	while (lo != hi) {
		mid = (lo + hi) / 2;
		Region* region = &regions[mid];
		if (region->start >= start) {
			hi = mid;
		} else {
			lo = mid + 1;
		}
	}
	return lo;
}

Bool register_readonly_region(ULong start, ULong size, unsigned char* content)
{
	// Where do we insert the region?
	if (next_unused_region_id >= MAX_REGION_COUNT) {
		// Regions are full
		return False;
	}

	int pos = find_region(start);
	if (pos < 0) {
		// Regions are full
		return False;
	}

	if (!regions[pos].in_use) {
		// it's likely to be the end - store here
		regions[pos].in_use = True;
		regions[pos].start = start;
		regions[pos].size = size;
		regions[pos].content = content;
		next_unused_region_id++;
		return True;
	}

	if (regions[pos].start == start) {
		// overwrite the current region with new data
		regions[pos].in_use = True;
		regions[pos].start = start;
		regions[pos].size = size;
		regions[pos].content = content;
		return True;
	}

	// Move everything forward by one slot
	memmove(&regions[pos + 1], &regions[pos], sizeof(Region) * (next_unused_region_id - pos));
	// Insert the new region
	regions[pos].in_use = True;
	regions[pos].start = start;
	regions[pos].size = size;
	regions[pos].content = content;
	next_unused_region_id++;
	return True;
}

void deregister_all_readonly_regions()
{
	next_unused_region_id = 0;
	regions[next_unused_region_id].in_use = 0;
}

Bool load_value(ULong addr, int size, int endness, void *value) {
	int pos = find_region(addr);
	if (pos < 0 || pos >= next_unused_region_id) {
		// Does not exist
		return False;
	}
	unsigned char* ptr = NULL;
	if (regions[pos].in_use &&
		regions[pos].start <= addr &&
		regions[pos].start <= addr + size &&
		regions[pos].start + regions[pos].size >= addr + size) {
		ptr = regions[pos].content + (addr - regions[pos].start);
	} else if (pos > 0 &&
			regions[pos - 1].in_use &&
			regions[pos - 1].start <= addr &&
			regions[pos - 1].start <= addr + size &&
			regions[pos - 1].start + regions[pos - 1].size >= addr + size) {
		ptr = regions[pos - 1].content + (addr - regions[pos - 1].start);
	} else {
		return False;
	}

	// Do the load!
	if ((endness == Iend_LE && LE_HOST) || (endness == Iend_BE && BE_HOST)) {
		switch (size) {
			case 1:
				*(UChar*)value = *(UChar*)ptr;
				break;
			case 2:
				*(UShort*)value = *(UShort*)ptr;
				break;
			case 4:
				*(UInt*)value = *(UInt*)ptr;
				break;
			case 8:
				*(ULong*)value = *(ULong*)ptr;
				break;
			default:
				{
					UChar* begin = (UChar*)value;
					for (int n = 0; n < size; ++n) {
						*(begin + n) = *(ptr + n);
					}
				}
				break;
		}
	} else {
		// we need to swap data...
		UChar* begin = (UChar*)value;
		for (int n = 0; n < size; ++n) {
			*(begin + size - n - 1) = *(ptr + n);
		}
	}
	return True;
}

#undef MAX_REGION_COUNT

typedef struct _InitialReg {
	ULong offset;
	UInt size;
	ULong value;
} InitialReg;
UInt initial_reg_count = 0;
InitialReg initial_regs[1024];


Bool register_initial_register_value(UInt offset, UInt size, ULong value)
{
	if (initial_reg_count >= 1024) {
		return False;
	}

	switch (size) {
		case 1: case 2: case 4: case 8: case 16:
			break;
		default:
			return False;
	}

	UInt i = initial_reg_count;
	initial_regs[i].offset = offset;
	initial_regs[i].size = size;
	initial_regs[i].value = value;
	initial_reg_count++;
	return True;
}

Bool reset_initial_register_values()
{
	initial_reg_count = 0;
	return True;
}


void execute_irsb(
	IRSB *irsb,
	VEXLiftResult *lift_r,
	VexArch guest,
	Bool load_from_ro_regions,
	Bool collect_data_refs,
	Bool const_prop
) {

	Int i;
	Addr inst_addr = -1, next_inst_addr = -1;
	HashHW* env = newHHW();
	TmpValue *tmps = NULL;
	TmpValue tmp_backingstore[1024];
    // Record the last legitimate constant value. We do not record RdTmp or BinOp results
    // if they are the same as the last constant.
	UInt last_const_value = 0;

	if (irsb->tyenv->types_used > 1024) {
		tmps = malloc(irsb->tyenv->types_used * sizeof(TmpValue));
	} else {
		tmps = tmp_backingstore;  // Use the local backing store to save a malloc
	}

	memset(tmps, 0, irsb->tyenv->types_used * sizeof(TmpValue));

	// Set initial register values
	for (i = 0; i < initial_reg_count; ++i) {
		IRType ty;
		switch (initial_regs[i].size) {
			case 1:
				ty = Ity_I8;
				break;
			case 2:
				ty = Ity_I16;
				break;
			case 4:
				ty = Ity_I32;
				break;
			case 8:
				ty = Ity_I64;
				break;
			case 16:
				ty = Ity_I128;
				break;
			default:
				continue;
		}
		UInt key = mk_key_GetPut(initial_regs[i].offset, ty);
		addToHHW(env, key, initial_regs[i].value);
	}

	for (i = 0; i < irsb->stmts_used; ++i) {
		IRStmt *stmt = irsb->stmts[i];
		switch (stmt->tag) {
		case Ist_IMark:
			inst_addr = stmt->Ist.IMark.addr + stmt->Ist.IMark.delta;
			next_inst_addr = inst_addr + stmt->Ist.IMark.len;
			break;
		case Ist_WrTmp:
			assert(inst_addr != -1 && next_inst_addr != -1);
			{
				IRExpr *data = stmt->Ist.WrTmp.data;
				switch (data->tag) {
				case Iex_Load:
					// load
					// e.g. t7 = LDle:I64(0x0000000000600ff8)
					if (data->Iex.Load.addr->tag == Iex_Const) {
						Int size;
						size = sizeofIRType(typeOfIRTemp(irsb->tyenv, stmt->Ist.WrTmp.tmp));
						Addr v = get_const_and_record(lift_r, data->Iex.Load.addr, size, Dt_Integer, i, inst_addr, next_inst_addr, collect_data_refs);
						if (v != -1 && v != next_inst_addr) {
							last_const_value = v;
						}
						// Load the value if it might be a constant pointer...
						if (load_from_ro_regions) {
							UInt value = 0;
							if (load_value(data->Iex.Load.addr->Iex.Const.con->Ico.U32, size, data->Iex.Load.end, &value)) {
								tmps[stmt->Ist.WrTmp.tmp].used = 1;
								tmps[stmt->Ist.WrTmp.tmp].value = value;
								if (const_prop) {
									record_tmp_value(lift_r, stmt->Ist.WrTmp.tmp, value, i);
								}
							}
						}
					} else if (data->Iex.Load.addr->tag == Iex_RdTmp) {
						IRTemp rdtmp = data->Iex.Load.addr->Iex.RdTmp.tmp;
						if (tmps[rdtmp].used == 1) {
							// The source tmp exists
							Int size;
							size = sizeofIRType(typeOfIRTemp(irsb->tyenv, stmt->Ist.WrTmp.tmp));
							if (tmps[rdtmp].value != last_const_value) {
								if (collect_data_refs) {
									record_data_reference(lift_r, tmps[rdtmp].value, size, Dt_Integer, i, inst_addr);
								}
							}
							if (load_from_ro_regions)
								if (guest == VexArchARM && size == 4 ||
									guest == VexArchMIPS32 && size == 4 ||
									guest == VexArchMIPS64 && size == 8) {
								ULong value = 0;
								if (load_value(tmps[rdtmp].value, size, data->Iex.Load.end, &value)) {
									tmps[stmt->Ist.WrTmp.tmp].used = 1;
									tmps[stmt->Ist.WrTmp.tmp].value = value;
									if (const_prop) {
										record_tmp_value(lift_r, stmt->Ist.WrTmp.tmp, value, i);
									}
								}
							}
						}
					}
					break;
				case Iex_Binop:
					if (data->Iex.Binop.op == Iop_Add32 || data->Iex.Binop.op == Iop_Add64) {
						IRExpr *arg1 = data->Iex.Binop.arg1, *arg2 = data->Iex.Binop.arg2;
						if (arg1->tag == Iex_Const && arg2->tag == Iex_Const) {
							// ip-related addressing
							Addr addr = get_value_from_const_expr(arg1->Iex.Const.con) +
								get_value_from_const_expr(arg2->Iex.Const.con);
							if (data->Iex.Binop.op == Iop_Add32) {
								addr &= 0xffffffff;
							}
							if (addr != next_inst_addr) {
								if (addr != last_const_value) {
									if (collect_data_refs) {
										record_data_reference(lift_r, addr, 0, Dt_Unknown, i, inst_addr);
									}
								}
							}
							if (const_prop) {
								record_tmp_value(lift_r, stmt->Ist.WrTmp.tmp, addr, i);
							}
						} else {
							// Do the calculation
							if (arg1->tag == Iex_RdTmp
								&& tmps[arg1->Iex.RdTmp.tmp].used
								&& arg2->tag == Iex_Const) {
								ULong arg1_value = tmps[arg1->Iex.RdTmp.tmp].value;
								ULong arg2_value = get_value_from_const_expr(arg2->Iex.Const.con);
								ULong value = arg1_value + arg2_value;
								if (data->Iex.Binop.op == Iop_Add32) {
									value &= 0xffffffff;
								}
								if (value != last_const_value) {
									if (collect_data_refs) {
										record_data_reference(lift_r, value, 0, Dt_Unknown, i, inst_addr);
									}
								}
								tmps[stmt->Ist.WrTmp.tmp].used = 1;
								tmps[stmt->Ist.WrTmp.tmp].value = value;
								if (const_prop) {
									record_tmp_value(lift_r, stmt->Ist.WrTmp.tmp, value, i);
								}
							}
							if (arg1->tag == Iex_Const
								&& arg2->tag == Iex_RdTmp
								&& tmps[arg2->Iex.RdTmp.tmp].used) {
								ULong arg1_value = get_value_from_const_expr(arg1->Iex.Const.con);
								ULong arg2_value = tmps[arg2->Iex.RdTmp.tmp].value;
								ULong value = arg1_value + arg2_value;
								if (data->Iex.Binop.op == Iop_Add32) {
									value &= 0xffffffff;
								}
								if (value != last_const_value) {
									if (collect_data_refs) {
										record_data_reference(lift_r, value, 0, Dt_Unknown, i, inst_addr);
									}
								}
								tmps[stmt->Ist.WrTmp.tmp].used = 1;
								tmps[stmt->Ist.WrTmp.tmp].value = value;
								if (const_prop) {
									record_tmp_value(lift_r, stmt->Ist.WrTmp.tmp, value, i);
								}
							}
							if (arg2->tag == Iex_Const) {
								ULong arg2_value = get_value_from_const_expr(arg2->Iex.Const.con);
								if (arg2_value != last_const_value) {
									if (collect_data_refs) {
										record_data_reference(lift_r, arg2_value, 0, Dt_Unknown, i, inst_addr);
									}
								}
							}
							if (arg1->tag == Iex_RdTmp
								&& tmps[arg1->Iex.RdTmp.tmp].used
								&& arg2->tag == Iex_RdTmp
								&& tmps[arg2->Iex.RdTmp.tmp].used) {
								ULong arg1_value = tmps[arg1->Iex.RdTmp.tmp].value;
								ULong arg2_value = tmps[arg2->Iex.RdTmp.tmp].value;
								ULong value = arg1_value + arg2_value;
								if (data->Iex.Binop.op == Iop_Add32) {
									value &= 0xffffffff;
								}
								tmps[stmt->Ist.WrTmp.tmp].used = 1;
								tmps[stmt->Ist.WrTmp.tmp].value = value;
								if (const_prop) {
									record_tmp_value(lift_r, stmt->Ist.WrTmp.tmp, value, i);
								}
							}
						}
					}
					else {
						// Normal binary operations
						if (data->Iex.Binop.arg1->tag == Iex_Const) {
							Addr v = get_const_and_record(lift_r, data->Iex.Binop.arg1, 0, Dt_Unknown, i, inst_addr, next_inst_addr, collect_data_refs);
							if (v != -1 && v != next_inst_addr) {
								last_const_value = v;
							}
						}
						if (data->Iex.Binop.arg2->tag == Iex_Const) {
							Addr v = get_const_and_record(lift_r, data->Iex.Binop.arg2, 0, Dt_Unknown, i, inst_addr, next_inst_addr, collect_data_refs);
							if (v != -1 && v != next_inst_addr) {
								last_const_value = v;
							}
						}
					}
					break;
				case Iex_Const:
					{
						Addr v = get_const_and_record(lift_r, data, 0, Dt_Unknown, i, inst_addr, next_inst_addr, collect_data_refs);
						if (v != -1 && v != next_inst_addr) {
							last_const_value = v;
						}
						Addr value = get_value_from_const_expr(data->Iex.Const.con);
						tmps[stmt->Ist.WrTmp.tmp].used = 1;
						tmps[stmt->Ist.WrTmp.tmp].value = value;
						if (const_prop) {
							record_tmp_value(lift_r, stmt->Ist.WrTmp.tmp, value, i);
						}
					}
					break;
				case Iex_ITE:
					{
						if (data->Iex.ITE.iftrue->tag == Iex_Const) {
							get_const_and_record(lift_r, data->Iex.ITE.iftrue, 0, Dt_Unknown, i, inst_addr, next_inst_addr, collect_data_refs);
						}
						if (data->Iex.ITE.iffalse->tag == Iex_Const) {
							get_const_and_record(lift_r, data->Iex.ITE.iffalse, 0, Dt_Unknown, i, inst_addr, next_inst_addr, collect_data_refs);
						}
					}
					break;
				case Iex_Get:
					{
						UInt key = mk_key_GetPut(data->Iex.Get.offset, data->Iex.Get.ty);
						HWord val;
						if (lookupHHW(env, &val, key) == True) {
							tmps[stmt->Ist.WrTmp.tmp].used = 1;
							tmps[stmt->Ist.WrTmp.tmp].value = val;
							if (const_prop) {
								record_tmp_value(lift_r, stmt->Ist.WrTmp.tmp, val, i);
							}
						}
					}
				default:
					// Unsupported for now
					break;
				} // end switch (data->tag)
			}
			break;
		case Ist_Put:
			// put
			// e.g. PUT(rdi) = 0x0000000000400714
			assert(inst_addr != -1 && next_inst_addr != -1);
			{
				// Ignore itstate on ARM
				if (guest == VexArchARM && stmt->Ist.Put.offset == offsetof(VexGuestARMState, guest_ITSTATE)) {
					break;
				}

				IRExpr *data = stmt->Ist.Put.data;
				if (data->tag == Iex_Const) {
					Addr v = get_const_and_record(lift_r, data, 0, Dt_Unknown, i, inst_addr, next_inst_addr, collect_data_refs);
					if (v != -1 && v != next_inst_addr) {
						last_const_value = v;
					}
					UInt key = mk_key_GetPut(stmt->Ist.Put.offset, typeOfIRExpr(irsb->tyenv, data));
					addToHHW(env, key, get_value_from_const_expr(data->Iex.Const.con));
				} else if (data->tag == Iex_RdTmp) {
					if (tmps[data->Iex.RdTmp.tmp].used == 1) {
						// tmp is available
						IRType data_type = typeOfIRExpr(irsb->tyenv, data);
						UInt key = mk_key_GetPut(stmt->Ist.Put.offset, data_type);
						ULong value = tmps[data->Iex.RdTmp.tmp].value;
						addToHHW(env, key, value);
						if (value != last_const_value) {
							if (collect_data_refs) {
								record_data_reference(lift_r, value, 0, Dt_Integer, i, inst_addr);
							}
						}
					}
					else {
						// the tmp does not exist; we ignore updates to GP on MIPS32
						// this is to handle cases where gp is loaded from a stack variable
						if (guest == VexArchMIPS32 && stmt->Ist.Put.offset == offsetof(VexGuestMIPS32State, guest_r28)) {
							break;
						}
						IRType data_type = typeOfIRExpr(irsb->tyenv, data);
						UInt key = mk_key_GetPut(stmt->Ist.Put.offset, data_type);
						removeFromHHW(env, key);
					}
				}
			}
			break;
		case Ist_Store:
			// Store
			assert(inst_addr != -1 && next_inst_addr != -1);
			{
				IRExpr *store_dst = stmt->Ist.Store.addr;
				IRExpr *store_data = stmt->Ist.Store.data;
				if (store_dst->tag == Iex_Const) {
					// Writing to a memory destination. We can get its size by analyzing the size of store_data
					IRType data_type = typeOfIRExpr(irsb->tyenv, stmt->Ist.Put.data);
					Int data_size = 0;
					if (data_type != Ity_INVALID) {
						data_size = sizeofIRType(data_type);
					}
					get_const_and_record(lift_r, store_dst, data_size,
						data_size == 0? Dt_Unknown : Dt_StoreInteger,
						i, inst_addr, next_inst_addr, collect_data_refs);
				}
				if (store_data->tag == Iex_Const) {
					get_const_and_record(lift_r, store_data, 0, Dt_Unknown, i, inst_addr, next_inst_addr, collect_data_refs);
				}
			}
			break;
		case Ist_Dirty:
			// Dirty
			assert(inst_addr != -1 && next_inst_addr != -1);
			if (stmt->Ist.Dirty.details->mAddr != NULL &&
				stmt->Ist.Dirty.details->mAddr->tag == Iex_Const) {
				IRExpr *m_addr = stmt->Ist.Dirty.details->mAddr;
				get_const_and_record(lift_r, m_addr, stmt->Ist.Dirty.details->mSize, Dt_FP, i, inst_addr, next_inst_addr, collect_data_refs);
			}
			break;
		case Ist_LoadG:
			// LoadG
			// e.g., t7 = if (t70) ILGop_Ident32(LDle(0x00032f50)) else t69
			if (stmt->Ist.LoadG.details->addr != NULL &&
				stmt->Ist.LoadG.details->addr->tag == Iex_Const) {
				IRExpr *addr = stmt->Ist.LoadG.details->addr;
				IRType data_type = typeOfIRExpr(irsb->tyenv, addr);
				Int data_size = 0;
				if (data_type != Ity_INVALID) {
					data_size = sizeofIRType(data_type);
				}
				get_const_and_record(lift_r, addr, data_size, Dt_Unknown, i, inst_addr, next_inst_addr, collect_data_refs);
			}
			break;
		default:
			break;
		} // end switch (stmt->tag)
	}

	freeHHW(env);
	if (tmps != tmp_backingstore) {
		free(tmps);
	}
}

/* Determine if the VEX block is an no-op */
void get_is_noop_block(
	IRSB *irsb, VEXLiftResult *lift_r
) {
	// the block is a noop block if it only has IMark statements **and** it jumps to its immediate successor. VEX will
	// generate such blocks when opt_level==1 and cross_insn_opt is True.

	// the block is a noop block if it only has IMark statements and IP-setting statements that set the IP to the next
	// location. VEX will generate such blocks when opt_level==1 and cross_insn_opt is False.
	Addr fallthrough_addr = 0xffffffffffffffff;
	Bool has_other_inst = False;

	for (int i = 0; i < irsb->stmts_used; ++i) {
		IRStmt *stmt = irsb->stmts[i];
		if (stmt->tag == Ist_IMark) {
			// update fallthrough_addr; it will be correct upon the last instruction
			fallthrough_addr = stmt->Ist.IMark.addr + stmt->Ist.IMark.delta + stmt->Ist.IMark.len;
		} else if (stmt->tag == Ist_NoOp) {
			// NoOp is a no-op
		} else if (stmt->tag == Ist_Put) {
			if (stmt->Ist.Put.data->tag == Iex_Const) {
				if (irsb->offsIP != stmt->Ist.Put.offset) {
					// found a register write that is not the same as the pc offset; this is not a noop block
					lift_r->is_noop_block = False;
					return;
				}
			} else {
				// found a non-constant register write; this is not a noop block
				lift_r->is_noop_block = False;
				return;
			}
		} else {
			has_other_inst = True;
			break;
		}
	}
	if (has_other_inst) {
		lift_r->is_noop_block = False;
		return;
	}

	if (fallthrough_addr == 0xffffffffffffffff) {
		// for some reason we cannot find the fallthrough addr; just give up
		lift_r->is_noop_block = False;
		return;
	}

	if (irsb->jumpkind == Ijk_Boring && irsb->next->tag == Iex_Const) {
		if (irsb->next->Iex.Const.con->tag == Ico_U32 && fallthrough_addr < 0xffffffff && fallthrough_addr == irsb->next->Iex.Const.con->Ico.U32
			|| irsb->next->Iex.Const.con->tag == Ico_U64 && fallthrough_addr == irsb->next->Iex.Const.con->Ico.U64) {
			lift_r->is_noop_block = True;
			return;
		}
	}

	lift_r->is_noop_block = False;
}
