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

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <unordered_set>

int
main (int argc, char *argv[])
{
  size_t size = 1000;
  // int *a = (int *)malloc (sizeof (*a) * size);
  // for (size_t i = 0; i < size; ++i)
  //   {
  //     a[i] = size - i - 1;
  //   }

  std::unordered_set<int> set;
  for (size_t i = 0; i < size; ++i)
    {
      set.insert (i);
    }
}