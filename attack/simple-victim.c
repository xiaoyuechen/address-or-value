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
#include <string.h>

static char s[8];

static unsigned char a[256 * 64];

void
access ()
{
  for (size_t i = 0; i < sizeof (s); ++i)
    {
      asm volatile("movq (%0), %%rax\n" : : "c"(a + s[i] * 64) : "rax");
    }
}

int
main (int argc, char *argv[argc + 1])
{
  if (argc > 1)
    {
      const char *secret = argv[1];
      memcpy (s, secret,
              strlen (secret) < sizeof (s) ? strlen (secret) : sizeof (s));
    }
  access ();
  exit (EXIT_SUCCESS);
}
