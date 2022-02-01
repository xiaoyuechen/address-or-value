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

static size_t b[] = { 0, 1, 2, 3, 4 };
static size_t a[] = { 1, 3, 5, 7, 9 };
const static size_t size = sizeof (a) / sizeof (a[0]);

int
main (int argc, char *argv[])
{
  printf ("a-b-i start\n");
  for (size_t i = 0; i < size; ++i)
    {
      printf ("%zu\n", a[b[i]]);
    }
  printf ("a-b-i end\n");
  return 0;
}