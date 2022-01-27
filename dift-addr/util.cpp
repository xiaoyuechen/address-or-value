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

#include "util.h"
#include "operand.hpp"
#include <string>

std::string
UT_InsOpString (INS ins)
{
  OP op[OP_MAX_OP_COUNT];
  int nop = INS_Operands (ins, op);

  static const size_t MAX_CHAR_COUNT = 256;
  char buff[MAX_CHAR_COUNT];
  int offset = snprintf (buff, MAX_CHAR_COUNT, "%s\n",
                         INS_Disassemble (ins).c_str ());

  for (int i = 0; i < nop; ++i)
    {
      offset += snprintf (buff + offset, MAX_CHAR_COUNT, "    OP %d: %s\n",
                          i + 1, OP_ToString (op[i]).c_str ());
    }

  return std::string (buff);
}
