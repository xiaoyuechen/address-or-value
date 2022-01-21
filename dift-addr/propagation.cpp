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

#include "propagation.h"

#include "operand.h"
#include "taint-table.h"
#include "util.h"
#include <algorithm>
#include <cstdio>

bool
OperandFilter (OP op)
{
  bool drop;
  switch (op.t)
    {
    case OP_T_REG:
      drop = !REG_is_gr (REG_FullRegName (op.content.reg));
      break;
    case OP_T_MEM:
    case OP_T_ADR:
      drop = false;
      break;
    case OP_T_IMM:
    case OP_T_NONE:
    default:
      drop = true;
      break;
    }
  return drop;
}

bool
InstructionFilter (INS ins)
{
  bool drop = INS_IsBranch (ins) || INS_IsCall (ins) || INS_IsNop (ins);
  return drop;
}

void
PG_InstrumentPropagation (INS ins)
{
  if (InstructionFilter (ins))
    {
      return;
    }

  OP op[OP_MAX_OP_COUNT];
  int nop = INS_Operands (ins, op);
  OP *op_last = std::remove_if (op, op + nop, OperandFilter);

  OP op_reg_w[OP_MAX_OP_COUNT];
  OP *op_reg_w_last = std::remove_copy_if (op, op_last, op_reg_w, [] (OP op) {
    return !(op.t == OP_T_REG && op.rw & OP_RW_W);
  });

  if (op_reg_w_last - op_reg_w >= 1)
    {
      printf ("%s", UT_InstructionOperandString (ins).c_str ());
    }
}
