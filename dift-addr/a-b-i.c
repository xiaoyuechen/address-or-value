/*
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

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

int
main (int argc, char *argv[])
{
  size_t sump = 0;
  size_t size = 1000;
  size_t *b = malloc (size * sizeof (*b));
  for (size_t i = 0; i < size; ++i)
    {
      b[i] = size - i - 1;
    }
  size_t *a = malloc (size * sizeof (*a));
  for (size_t i = 0; i < size; ++i)
    {
      sump += a[b[i]];
    }
  printf ("sum %zu\n", sump);
  return 0;
}
