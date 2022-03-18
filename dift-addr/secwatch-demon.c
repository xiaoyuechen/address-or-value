/*
 * dift-addr --- Dynamic Information Flow Tracking on memory ADDResses
 * Copyright (C) 2022  Xiaoyue Chen
 *
 * This file is part of dift-addr.
 *
 * dift-addr is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * dift-addr is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with dift-addr.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "secwatch.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char a[256 * 64];
static const char s1_str[] = "TOp";
static const char s2_str[] = "sEcRet";

void
access (char *data, size_t n)
{
  for (size_t i = 0; i < n; ++i)
    {
      asm volatile("movq (%0), %%rax\n" : : "c"(a + data[i] * 64) : "rax");
    }
}

int
main (int argc, char *argv[argc + 1])
{
  char *s1 = malloc (sizeof (s1_str));
  SEC_Watch (s1, sizeof (s1_str));
  strcpy (s1, s1_str);
  access (s1, 8);
  SEC_Unwatch (s1);

  char *s2 = malloc (sizeof (s2_str));
  SEC_Watch (s2, sizeof (s2_str));
  strcpy (s2, s2_str);
  access (s2, 8);
  SEC_Unwatch (s2);

  exit (EXIT_SUCCESS);
}
