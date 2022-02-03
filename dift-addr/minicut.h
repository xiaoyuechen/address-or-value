/*
 * minicut --- MINI C Unit Test
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

#ifndef MINICUT_H
#define MINICUT_H

#include <stdio.h>
#include <stdlib.h>

static void __MC_add_test (int (*f) (void));

#define MC_ASSERT(b)                                                          \
  do                                                                          \
    {                                                                         \
      if (!(b))                                                               \
        {                                                                     \
          *__MC_test_status = 1;                                              \
          fprintf (stderr, "\n%s:%lu: Assertion failed: %s", __FILE__,        \
                   __LINE__ + 0UL, #b);                                       \
          fflush (stderr);                                                    \
        }                                                                     \
    }                                                                         \
  while (0)

#define MC_TEST(name)                                                         \
  static int __MC_wrap_##name (void);                                         \
  static void __MC_real_##name (int *);                                       \
                                                                              \
  static void __attribute__ ((constructor)) __MC_construct_##name (void)      \
  {                                                                           \
    __MC_add_test (__MC_wrap_##name);                                         \
  }                                                                           \
                                                                              \
  static int __MC_wrap_##name (void)                                          \
  {                                                                           \
    int __MC_test_status = 0;                                                 \
    printf ("%s... ", #name);                                                 \
    fflush (stdout);                                                          \
    __MC_real_##name (&__MC_test_status);                                     \
    if (!__MC_test_status)                                                    \
      {                                                                       \
        printf ("\tOK\n");                                                    \
      }                                                                       \
    else                                                                      \
      {                                                                       \
        printf ("\n");                                                        \
      }                                                                       \
    return __MC_test_status;                                                  \
  }                                                                           \
                                                                              \
  static void __MC_real_##name (int *__MC_test_status)

typedef struct __MC_test_node
{
  struct __MC_test_node *next;
  int (*func) (void);
} __MC_test_node;

static __MC_test_node *__MC_test_head = 0;

static void
__MC_add_test (int (*f) (void))
{
  __MC_test_node **current = &__MC_test_head;
  while (*current)
    current = &((*current)->next);
  *current = (__MC_test_node *)malloc (sizeof (__MC_test_node));
  (*current)->next = 0;
  (*current)->func = f;
}

int
main ()
{
  int total_tests = 0;
  int failed_tests = 0;
  __MC_test_node *current = __MC_test_head;
  while (current)
    {
      ++total_tests;
      if (current->func () != 0)
        {
          ++failed_tests;
        }
      current = current->next;
    }
  printf ("\n%d tests: %d passed, %d failed\n", total_tests,
          total_tests - failed_tests, failed_tests);
  int exit_status = failed_tests ? 1 : 0;
  exit (exit_status);
}

#endif
