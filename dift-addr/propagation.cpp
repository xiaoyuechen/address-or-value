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
#include "types_core.PH"
#include "util.hpp"
#include <algorithm>
#include <stddef.h>
#include <stdio.h>

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
CopyRegFromMemOp (REG *dst, const OP *const op, size_t n, OP_T t, OP_RW rw)
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
  size_t nadr_reg = CopyRegFromMemOp (dst + nreg_reg, op, n, OP_T_ADR, rw);
  return nreg_reg + nadr_reg;
}

#define REG_T_LIST                                                            \
  X (REG)                                                                     \
  X (MEM)

void
PG_InstrumentPropagation (INS ins)
{
  if (!IsInsRelevant (ins))
    {
      return;
    }

  OP op[OP_MAX_OP_COUNT];
  size_t nop = std::remove_if (op, op + INS_Operands (ins, op),
                               [] (OP op) { return !IsOpRelevant (op); })
               - op;

  REG reg_r[OP_MAX_OP_COUNT];
  size_t nreg_r = CopyReg (reg_r, op, nop, OP_RW_R);

  REG reg_w[OP_MAX_OP_COUNT];
  size_t nreg_w = CopyReg (reg_w, op, nop, OP_RW_W);

  printf ("%s", UT_InsOpString (ins).c_str ());
  printf ("    REG_R: ");
  for (size_t i = 0; i < nreg_r; ++i)
    {
      printf ("%s ", REG_StringShort (reg_r[i]).c_str ());
    }
  printf ("\n");
  printf ("    REG_W: ");
  for (size_t i = 0; i < nreg_w; ++i)
    {
      printf ("%s ", REG_StringShort (reg_w[i]).c_str ());
    }
  printf ("\n");
}
