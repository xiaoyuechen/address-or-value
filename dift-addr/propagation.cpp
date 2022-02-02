/*
 * dift-addr --- DIFT on memory addresses
 * Copyright (C) 2022  Xiaoyue Chen
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "propagation.hpp"

#include "operand.hpp"
#include "taint-table.hpp"
#include "types_base.PH"
#include "types_core.PH"
#include "types_vmapi.PH"
#include "util.hpp"
#include "xed-iclass-enum.h"
#include "xed-reg-enum.h"
#include <algorithm>
#include <set>
#include <stddef.h>
#include <stdio.h>
#include <types.h>
#include <vector>

static constexpr size_t TT_NUM_TAINT = 16;
static constexpr size_t TT_TMP_ROW = REG_GR_LAST + 1;
static TAINT_TABLE<TT_TMP_ROW + 1, TT_NUM_TAINT> tt;
static ADDRINT tea[TT_NUM_TAINT];
static std::set<ADDRINT> addr_mem;
static std::set<ADDRINT> addr_any;
static std::map<ADDRINT, std::string> disassemble;

bool
IsRegRelevant (REG reg)
{
  return REG_valid (reg) && REG_is_gr (REG_FullRegName (reg));
}

bool
IsOpRelevant (OP op)
{
  bool relevant = false;
  switch (op.t)
    {
    case OP_T_REG:
      relevant = IsRegRelevant (op.content.reg);
      break;

    case OP_T_MEM:
      relevant = true;
      break;

    case OP_T_ADR:
      relevant = IsRegRelevant (op.content.mem.base)
                 || IsRegRelevant (op.content.mem.index);
      break;

    case OP_T_IMM:
    case OP_T_NONE:
    default:
      break;
    }
  return relevant;
}

bool
IsInsRelevant (INS ins)
{
  bool irrelevant = INS_IsBranch (ins) || INS_IsCall (ins) || INS_IsNop (ins);
  return !irrelevant;
}

size_t
FilterOp (OP *dst, const OP *const op, size_t n, OP_T type, OP_RW rw)
{
  OP *last = std::remove_copy_if (op, op + n, dst, [=] (OP op) {
    return !(op.t == type && (op.rw & rw) == rw);
  });
  return last - dst;
}

void
TransformToFullReg (REG *dst, REG *const src, size_t n)
{
  std::transform (src, src + n, dst,
                  [] (REG reg) { return REG_FullRegName (reg); });
}

size_t
CopyMemReg (REG *dst, const OP *const op, size_t n, OP_T t, OP_RW rw)
{
  OP adr[OP_MAX_OP_COUNT];
  size_t nadr = FilterOp (adr, op, n, t, rw);
  size_t nreg = 0;
  for (size_t i = 0; i < nadr; ++i)
    {
      if (IsRegRelevant (adr[i].content.mem.base))
        {
          dst[nreg++] = adr[i].content.mem.base;
        }
      if (IsRegRelevant (adr[i].content.mem.index))
        {
          dst[nreg++] = adr[i].content.mem.index;
        }
    }
  return nreg;
}

size_t
CopyReg (REG *dst, const OP *const op, size_t n, OP_RW rw)
{
  auto copy_reg_reg = [] (REG *dst, const OP *const op, size_t n, OP_RW rw) {
    OP reg[OP_MAX_OP_COUNT];
    size_t nreg = FilterOp (reg, op, n, OP_T_REG, rw);
    std::transform (reg, reg + nreg, dst,
                    [] (OP op) { return op.content.reg; });
    return nreg;
  };

  size_t nreg_reg = copy_reg_reg (dst, op, n, rw);
  size_t nadr_reg = CopyMemReg (dst + nreg_reg, op, n, OP_T_ADR, rw);
  return nreg_reg + nadr_reg;
}

void
PropagateMemToReg (REG reg_w1, REG reg_w2, REG mem_r1, REG mem_r2, ADDRINT ea)
{
  {
    REG mem_r[] = { mem_r1, mem_r2 };
    for (REG mem : mem_r)
      {
        for (size_t t = 0; t < TT_NUM_TAINT; ++t)
          {
            if (tt.IsTainted (mem, t))
              {
                tt.UntaintCol (t);
                addr_mem.insert (tea[t]);
              }
          }
      }
  }

  {
    size_t t = tt.NextAvailableTaint ();
    tea[t] = ea;
    REG reg_w[] = { reg_w1, reg_w2 };
    for (REG reg : reg_w)
      {
        if (IsRegRelevant (reg))
          {
            tt.Taint (reg, t);
          }
      }
  }
}

void
PropagateRegToMem (REG mem_w1, REG mem_w2, REG reg_r1, REG reg_r2, ADDRINT ea)
{
  {
    REG mem_w[] = { mem_w1, mem_w2 };
    for (REG mem : mem_w)
      {
        for (size_t t = 0; t < TT_NUM_TAINT; ++t)
          {
            if (tt.IsTainted (mem, t))
              {
                tt.UntaintCol (t);
                addr_mem.insert (tea[t]);
              }
          }
      }
  }

  addr_mem.erase (ea);

  // TODO: Propagate to stack memory
}

void
PropagateRegToReg (REG w1, REG w2, REG r1, REG r2, REG r3)
{
  REG reg_w[] = { w1, w2 };
  REG reg_r[] = { r1, r2, r3 };
  for (REG r : reg_r)
    {
      tt.Union (TT_TMP_ROW, TT_TMP_ROW, r);
    }
  for (REG w : reg_w)
    {
      if (IsRegRelevant (w))
        {
          tt.Diff (w, w, w);
          tt.Union (w, TT_TMP_ROW, TT_TMP_ROW);
        }
    }
  tt.Diff (TT_TMP_ROW, TT_TMP_ROW, TT_TMP_ROW);
}

void
PropagateClear (REG r)
{
  tt.Diff (r, r, r);
}

void
InsertAddr (ADDRINT addr)
{
  addr_any.insert (addr);
}

void
PrintPropagateDebugMsg (ADDRINT addr)
{
  // printf ("%s\n", disassemble[addr].c_str ());
  // printf ("%s\n%s", disassemble[addr].c_str (), tt.ToString ("    ").c_str ());
  // printf ("    addr ");
  // for (ADDRINT a : addr_mem)
  //   {
  //     printf ("%p ", (void *)a);
  //   }
  // printf ("\n");
}

void
PG_InstrumentPropagation (INS ins)
{
  if (!IsInsRelevant (ins))
    {
      return;
    }

  disassemble[INS_Address (ins)] = INS_Disassemble (ins);

  tt.Diff (REG_INVALID (), REG_INVALID (), REG_INVALID ());

  OP op[OP_MAX_OP_COUNT];
  size_t nop = std::remove_if (op, op + INS_Operands (ins, op),
                               [] (OP op) { return !IsOpRelevant (op); })
               - op;

  REG reg_r[OP_MAX_OP_COUNT] = {};
  size_t nreg_r = CopyReg (reg_r, op, nop, OP_RW_R);
  TransformToFullReg (reg_r, reg_r, nreg_r);

  REG reg_w[OP_MAX_OP_COUNT] = {};
  size_t nreg_w = CopyReg (reg_w, op, nop, OP_RW_W);
  TransformToFullReg (reg_w, reg_w, nreg_w);

  REG mem_r[OP_MAX_OP_COUNT] = {};
  size_t nmem_r = CopyMemReg (mem_r, op, nop, OP_T_MEM, OP_RW_R);
  TransformToFullReg (mem_r, mem_r, nmem_r);

  REG mem_w[OP_MAX_OP_COUNT] = {};
  size_t nmem_w = CopyMemReg (mem_w, op, nop, OP_T_MEM, OP_RW_W);
  TransformToFullReg (mem_w, mem_w, nmem_w);

  INS_InsertCall (ins, IPOINT_BEFORE, (AFUNPTR)PropagateRegToReg, IARG_UINT32,
                  reg_w[0], IARG_UINT32, reg_w[1], IARG_UINT32, reg_r[0],
                  IARG_UINT32, reg_r[1], IARG_UINT32, reg_r[2], IARG_END);

  if (INS_IsMemoryRead (ins))
    {
      INS_InsertCall (ins, IPOINT_BEFORE, (AFUNPTR)PropagateMemToReg,
                      IARG_UINT32, reg_w[0], IARG_UINT32, reg_w[1],
                      IARG_UINT32, mem_r[0], IARG_UINT32, mem_r[1],
                      IARG_MEMORYREAD_EA, IARG_END);
      INS_InsertCall (ins, IPOINT_BEFORE, (AFUNPTR)InsertAddr,
                      IARG_MEMORYREAD_EA, IARG_END);
    }

  if (INS_IsMemoryWrite (ins))
    {
      INS_InsertCall (ins, IPOINT_BEFORE, (AFUNPTR)PropagateRegToMem,
                      IARG_UINT32, mem_w[0], IARG_UINT32, mem_w[1],
                      IARG_UINT32, reg_r[0], IARG_UINT32, reg_r[1],
                      IARG_MEMORYWRITE_EA, IARG_END);
      INS_InsertCall (ins, IPOINT_BEFORE, (AFUNPTR)InsertAddr,
                      IARG_MEMORYWRITE_EA, IARG_END);
    }

  if (INS_Opcode (ins) == XED_ICLASS_XOR && reg_r[0] == reg_w[0])
    {
      INS_InsertCall (ins, IPOINT_BEFORE, (AFUNPTR)PropagateClear, IARG_UINT32,
                      reg_r[0], IARG_END);
    }

  INS_InsertCall (ins, IPOINT_BEFORE, (AFUNPTR)PrintPropagateDebugMsg,
                  IARG_ADDRINT, INS_Address (ins), IARG_END);
}

VOID
PG_Fini (INT32 code, VOID *)
{
  printf ("%zu addresses out of %zu; %zu exhaustion\n", addr_mem.size (),
          addr_any.size (), tt.GetExhaustionCount ());
  for (ADDRINT a : addr_mem)
    {
      printf ("%p\n", (void *)a);
    }
}
