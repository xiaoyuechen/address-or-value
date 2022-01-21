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

#ifndef OPERAND_H
#define OPERAND_H

#include "pin.H"
#include <string>

#ifndef OP_MAX_OP_COUNT
#define OP_MAX_OP_COUNT 16
#endif

#define OP_T_LIST                                                             \
  X0 (NONE)                                                                   \
  X (IMM)                                                                     \
  X (REG)                                                                     \
  X (MEM)                                                                     \
  X (ADR)

typedef enum
{
#define X(name) OP_T_##name,
#define X0(name) X (name)
  OP_T_LIST
#undef X0
#undef X
      OP_T_COUNT
} OP_T;

typedef enum
{
  OP_RW_NONE = 0,
  OP_RW_R = 1 << 0,
  OP_RW_W = 1 << 1
} OP_RW;

typedef struct OP
{
  OP_T t;
  OP_RW rw;

  union CONTENT
  {
    REG reg;
    struct MEM
    {
      REG base, index;
    } mem;
  } content;
} OP;

std::string OP_ToString (OP op);

OP_T OP_Type (INS ins, UINT32 n);

int INS_Operands (INS ins, OP *op);

#endif
