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

#include "operand.hpp"
#include "taint-table.hpp"
#include <cstdio>

extern "C"
{
#include "minicut.h"
}

MC_TEST (atest)
{
  MC_ASSERT (true);
  MC_ASSERT (0 == 1);
  MC_ASSERT (1 == 2);
  MC_ASSERT (1 == 3);
  MC_ASSERT (true);
}

MC_TEST (btest) { MC_ASSERT (true); }

MC_TEST (ctest) { MC_ASSERT (true); }
