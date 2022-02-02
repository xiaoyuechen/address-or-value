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

#ifndef TAINT_TABLE_H
#define TAINT_TABLE_H

#include "operand.hpp"
#include "pin.H"
#include <algorithm>
#include <bitset>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <sstream>
#include <string>

template <size_t NUM_ROW, size_t NUM_TAINT> class TAINT_TABLE
{
public:
  using ROW = size_t;
  using TAINT = size_t;

  bool
  IsTainted (ROW row, TAINT taint) const
  {
    assert (row < NUM_ROW && taint < NUM_TAINT);

    return table_[row][taint];
  }

  void
  Taint (ROW row, TAINT taint)
  {
    assert (row < NUM_ROW && taint < NUM_TAINT);

    if (table_[row][taint])
      return;

    table_[row][taint] = true;

    timestamp_[taint] = time_++;
  }

  void
  Untaint (ROW row, TAINT taint)
  {
    assert (row < NUM_ROW && taint < NUM_TAINT);

    if (!table_[row][taint])
      return;

    table_[row][taint] = false;
  }

  void
  UntaintCol (TAINT taint)
  {
    assert (taint < NUM_TAINT);

    for (size_t row = 0; row < NUM_ROW; ++row)
      {
        Untaint (row, taint);
      }
  }

  void
  Union (ROW dst, ROW src1, ROW src2)
  {
    assert (dst < NUM_ROW && src1 < NUM_ROW && src2 < NUM_ROW);

    table_[dst] = table_[src1] | table_[src2];
  }

  void
  Diff (ROW dst, ROW src1, ROW src2)
  {
    assert (dst < NUM_ROW && src1 < NUM_ROW && src2 < NUM_ROW);

    table_[dst] = table_[src1] ^ table_[src2];
  }

  TAINT
  NextAvailableTaint ()
  {
    TAINT taint;

    size_t taint_count[NUM_TAINT]{};
    for (ROW r = 0; r < NUM_ROW; ++r)
      {
        for (TAINT t = 0; t < NUM_TAINT; ++t)
          {
            taint_count[t] += table_[r][t];
          }
      }

    size_t *available = std::find (taint_count, taint_count + NUM_TAINT, 0);
    if (available != taint_count + NUM_TAINT)
      {
        taint = available - taint_count;
      }
    else
      {
        size_t *oldest = std::min_element (timestamp_, timestamp_ + NUM_TAINT);
        taint = oldest - timestamp_;
        UntaintCol (taint);

        ++exhaustion_count_;

        // printf ("EXHAUSTION\n");
      }

    return taint;
  }

  std::string
  ToString (const char *sl = "") const
  {
    std::stringstream buff{};
    for (const std::bitset<NUM_TAINT> *it = table_ + 3; it != table_ + NUM_ROW;
         ++it)
      {
        buff << sl << REG_StringShort ((REG)(it - table_)) << "\t" << *it
             << "\n";
      }
    return buff.str ();
  }

  size_t
  GetExhaustionCount () const
  {
    return exhaustion_count_;
  }

private:
  std::bitset<NUM_TAINT> table_[NUM_ROW]{};
  size_t time_ = 0;
  size_t timestamp_[NUM_TAINT]{};
  size_t exhaustion_count_ = 0;
};

#endif
