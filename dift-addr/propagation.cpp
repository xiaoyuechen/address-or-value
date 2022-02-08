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
#include <cstdarg>
#include <cstddef>
#include <cstdio>
#include <set>
#include <string>
#include <types.h>
#include <unordered_map>
#include <vector>

static constexpr size_t TT_NUM_TAINT = 16;
static constexpr size_t TT_TMP_ROW = REG_GR_LAST + 1;
static TAINT_TABLE<TT_TMP_ROW + 1, TT_NUM_TAINT> tt;
static void *tea[TT_NUM_TAINT];
static std::set<void *> addr_mem;
static std::set<void *> addr_any;
static std::unordered_map<void *, std::string> disassemble;

struct RegArray
{
  static constexpr size_t MAX_NREG = 16;
  REG data[MAX_NREG];
  size_t size;
};

struct InsReg
{
  RegArray reg_w, reg_r, mem_w, mem_r;
};

static std::unordered_map<void *, InsReg> ins_reg_table;

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

size_t
FilterReg (REG *reg, size_t n)
{
  REG *last = std::remove_if (reg, reg + n,
                              [] (REG reg) { return !IsRegRelevant (reg); });
  return last - reg;
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
PropagateRegToReg (const uint32_t *w, size_t nw, const uint32_t *r, size_t nr)
{
  for (size_t i = 0; i < nr; ++i)
    {
      tt.Union (TT_TMP_ROW, TT_TMP_ROW, r[i]);
    }
  for (size_t i = 0; i < nw; ++i)
    {
      tt.Diff (w[i], w[i], w[i]);
      tt.Union (w[i], TT_TMP_ROW, TT_TMP_ROW);
    }
  tt.Diff (TT_TMP_ROW, TT_TMP_ROW, TT_TMP_ROW);
}

void
PropagateMemToReg (const uint32_t *reg_w, size_t nreg_w, const uint32_t *mem_r,
                   size_t nmem_r, void *ea, bool should_track)
{
  for (size_t i = 0; i < nmem_r; ++i)
    for (size_t t = 0; t < TT_NUM_TAINT; ++t)
      if (tt.IsTainted (mem_r[i], t))
        {
          tt.UntaintCol (t);
          addr_mem.insert (tea[t]);
        }

  for (size_t i = 0; i < nreg_w; ++i)
    {
      tt.Diff (reg_w[i], reg_w[i], reg_w[i]);
    }

  if (should_track)
    {
      size_t t = tt.NextAvailableTaint ();
      tea[t] = ea;
      for (size_t i = 0; i < nreg_w; ++i)
        {
          tt.Taint (reg_w[i], t);
        }
    }
}

void
PropagateRegToMem (const uint32_t *mem_w, size_t nmem_w, const uint32_t *reg_r,
                   size_t nreg_r, void *ea)
{
  {
    for (size_t i = 0; i < nmem_w; ++i)
      {
        for (size_t t = 0; t < TT_NUM_TAINT; ++t)
          {
            if (tt.IsTainted (mem_w[i], t))
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
PropagateClear (uint32_t r)
{
  tt.Diff (r, r, r);
}

void
InsertAddr (void *addr)
{
  addr_any.insert (addr);
}

void
PrintPropagateDebugMsg (void *addr)
{
  std::string (*row_to_reg) (size_t)
      = [] (size_t row) { return "\t" + REG_StringShort ((REG)row) + "\t"; };
  printf ("%s\n%s", disassemble[addr].c_str (),
          tt.ToString (row_to_reg, REG_GR_BASE, REG_GR_LAST).c_str ());
  printf ("\taddr { ");
  for (void *a : addr_mem)
    {
      printf ("%p ", a);
    }
  printf ("}\n");
}

void
PG_InstrumentPropagation (INS ins)
{
  if (!IsInsRelevant (ins))
    return;

  disassemble[(void *)INS_Address (ins)] = INS_Disassemble (ins);

  if (!ins_reg_table.count ((void *)INS_Address (ins)))
    {
      InsReg &regs = ins_reg_table[(void *)INS_Address (ins)];
      OP op[OP_MAX_OP_COUNT];
      size_t nop = std::remove_if (op, op + INS_Operands (ins, op),
                                   [] (OP op) { return !IsOpRelevant (op); })
                   - op;

      regs.reg_r.size = CopyReg (regs.reg_r.data, op, nop, OP_RW_R);
      TransformToFullReg (regs.reg_r.data, regs.reg_r.data, regs.reg_r.size);

      regs.reg_w.size = CopyReg (regs.reg_w.data, op, nop, OP_RW_W);
      TransformToFullReg (regs.reg_w.data, regs.reg_w.data, regs.reg_w.size);

      regs.mem_r.size
          = CopyMemReg (regs.mem_r.data, op, nop, OP_T_MEM, OP_RW_R);
      TransformToFullReg (regs.mem_r.data, regs.mem_r.data, regs.mem_r.size);

      regs.mem_w.size
          = CopyMemReg (regs.mem_w.data, op, nop, OP_T_MEM, OP_RW_W);
      TransformToFullReg (regs.mem_w.data, regs.mem_w.data, regs.mem_w.size);
    }

  const InsReg &regs = ins_reg_table[(void *)INS_Address (ins)];

  if (!regs.mem_r.size)
    {
      INS_InsertCall (
          ins, IPOINT_BEFORE, (AFUNPTR)PropagateRegToReg,           //
          IARG_PTR, regs.reg_w.data, IARG_ADDRINT, regs.reg_w.size, //
          IARG_PTR, regs.reg_r.data, IARG_ADDRINT, regs.reg_r.size, //
          IARG_END);
    }

  if (regs.mem_r.size)
    {
      // We do not care about tainting stack memory
      bool should_track
          = std::find_if (
                regs.mem_r.data, regs.mem_r.data + regs.mem_r.size,
                [] (REG mem) { return mem == REG_RBP || mem == REG_RSP; })
            == regs.mem_r.data + regs.mem_r.size;

      INS_InsertCall (
          ins, IPOINT_BEFORE, (AFUNPTR)PropagateMemToReg,           //
          IARG_PTR, regs.reg_w.data, IARG_ADDRINT, regs.reg_w.size, //
          IARG_PTR, regs.mem_r.data, IARG_ADDRINT, regs.mem_r.size, //
          IARG_MEMORYREAD_EA,                                       //
          IARG_BOOL, should_track,                                  //
          IARG_END);
      INS_InsertCall (ins, IPOINT_BEFORE, (AFUNPTR)InsertAddr,
                      IARG_MEMORYREAD_EA, IARG_END);
    }

  if (regs.mem_w.size)
    {
      INS_InsertCall (
          ins, IPOINT_BEFORE, (AFUNPTR)PropagateRegToMem,           //
          IARG_PTR, regs.mem_w.data, IARG_ADDRINT, regs.mem_w.size, //
          IARG_PTR, regs.reg_r.data, IARG_ADDRINT, regs.reg_r.size, //
          IARG_MEMORYWRITE_EA,                                      //
          IARG_END);
      INS_InsertCall (ins, IPOINT_BEFORE, (AFUNPTR)InsertAddr,
                      IARG_MEMORYWRITE_EA, IARG_END);
    }

  if (INS_Opcode (ins) == XED_ICLASS_XOR && regs.reg_r.size && regs.reg_w.size
      && regs.reg_r.data[0] == regs.reg_w.data[0])
    {
      INS_InsertCall (ins, IPOINT_BEFORE, (AFUNPTR)PropagateClear, IARG_UINT32,
                      regs.reg_r.data[0], IARG_END);
    }

  // INS_InsertCall (ins, IPOINT_BEFORE, (AFUNPTR)PrintPropagateDebugMsg,
  //                 IARG_ADDRINT, INS_Address (ins), IARG_END);
}

VOID
PG_Fini (INT32 code, VOID *)
{
  printf ("%zu addresses out of %zu; %zu exhaustion\n", addr_mem.size (),
          addr_any.size (), tt.GetExhaustionCount ());
  for (void *a : addr_mem)
    {
      printf ("%p\n", a);
    }
}
