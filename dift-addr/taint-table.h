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

#include <algorithm>
#include <bitset>
#include <cstddef>
#include <cstdint>

using TAINT = size_t;

template <size_t NUM_ROW, size_t NUM_TAINT> class TAINT_TABLE
{
public:
  bool
  IsTainted (size_t row, TAINT taint) const
  {
    return table_[row][taint];
  }

  void
  Taint (size_t row, TAINT taint)
  {
    if (table_[row][taint])
      return;

    table_[row][taint] = true;
    ++taint_count_[taint];

    timestamp_[taint] = time_++;
  }

  void
  Untaint (size_t row, TAINT taint)
  {
    if (!table_[row][taint])
      return;

    table_[row][taint] = false;
    --taint_count_[taint];
  }

  TAINT
  NextAvailableTaint ()
  {
    TAINT taint;

    size_t *available = std::find (taint_count_, taint_count_ + NUM_TAINT, 0);
    if (available != taint_count_ + NUM_TAINT)
      {
        taint = available - taint_count_;
      }
    else
      {
        size_t *oldest = std::min_element (timestamp_, timestamp_ + NUM_TAINT);
        taint = oldest - timestamp_;

        for (size_t row = 0; row < NUM_ROW; ++row)
          {
            Untaint (row, taint);
          }

        ++exhaustion_count_;
      }

    return taint;
  }

private:
  std::bitset<NUM_TAINT> table_[NUM_ROW]{};
  size_t taint_count_[NUM_TAINT]{ 0 };
  size_t time_ = 0;
  size_t timestamp_[NUM_TAINT]{ 0 };
  size_t exhaustion_count_ = 0;
};

#endif
