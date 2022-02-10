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

#include "propagation.h"

#include "taint-table.hpp"
#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <set>
#include <vector>

static constexpr size_t TT_TMP_ROW = TT_NUM_ROW + 1;
using PG_TAINT_TABLE = TAINT_TABLE<TT_TMP_ROW + 1, TT_NUM_TAINT>;

struct ADDRESS_CALLBACK
{
  PG_ADDRESS_HOOK_FN fn;
  void *user_ptr;
};

using PG_ADDRESS_HOOK = std::vector<ADDRESS_CALLBACK>;

enum ADDRESS_HOOK_TYPE
{
  PG_AH_MARK,
  PG_AH_UNMARK,
  PG_AH_COUNT,
};

struct PG_PROPAGATOR
{
  PG_TAINT_TABLE tt{};
  void *tea[TT_NUM_TAINT] = {};
  PG_ADDRESS_HOOK address_hook[PG_AH_COUNT];
};

PG_PROPAGATOR *
PG_CreatePropagator ()
{
  return new PG_PROPAGATOR{};
}

void
PG_DestroyPropagator (PG_PROPAGATOR *pg)
{
  delete pg;
}

void
PG_AddToAddressMarkHook (PG_PROPAGATOR *pg, PG_ADDRESS_HOOK_FN fn,
                         void *user_ptr)
{
  pg->address_hook[PG_AH_MARK].emplace_back (ADDRESS_CALLBACK{ fn, user_ptr });
}

void
PG_AddToAddressUnmarkHook (PG_PROPAGATOR *pg, PG_ADDRESS_HOOK_FN fn,
                           void *user_ptr)
{
  pg->address_hook[PG_AH_UNMARK].emplace_back (
      ADDRESS_CALLBACK{ fn, user_ptr });
}

void
InvokeAddressCallbacks (const ADDRESS_CALLBACK *callback, size_t n, void *ea)
{
  for (size_t i = 0; i < n; ++i)
    {
      callback[i].fn (ea, callback[i].user_ptr);
    }
}

void
PG_PropagateRegToReg (PG_PROPAGATOR *pg, const uint32_t *w, size_t nw,
                      const uint32_t *r, size_t nr)
{
  PG_TAINT_TABLE &tt = pg->tt;
  for (size_t i = 0; i < nr; ++i)
    {
      tt.Union (TT_TMP_ROW, TT_TMP_ROW, r[i]);
    }
  for (size_t i = 0; i < nw; ++i)
    {
      tt.Diff (w[i], w[i], w[i]);
      tt.Union (w[i], TT_TMP_ROW, TT_TMP_ROW);
    }
  tt.Diff (TT_TMP_ROW, TT_TMP_ROW, TT_TMP_ROW);
}

void
PG_PropagateMemToReg (PG_PROPAGATOR *pg, const uint32_t *reg_w, size_t nreg_w,
                      const uint32_t *mem_r, size_t nmem_r, void *ea)
{
  PG_TAINT_TABLE &tt = pg->tt;
  void **tea = pg->tea;

  for (size_t i = 0; i < nmem_r; ++i)
    for (size_t t = 0; t < TT_NUM_TAINT; ++t)
      if (tt.IsTainted (mem_r[i], t))
        {
          tt.UntaintCol (t);
          InvokeAddressCallbacks (&pg->address_hook[PG_AH_MARK][0],
                                  pg->address_hook[PG_AH_MARK].size (),
                                  tea[t]);
        }

  for (size_t i = 0; i < nreg_w; ++i)
    {
      tt.Diff (reg_w[i], reg_w[i], reg_w[i]);
    }

  size_t t = tt.NextAvailableTaint ();
  tea[t] = ea;
  for (size_t i = 0; i < nreg_w; ++i)
    {
      tt.Taint (reg_w[i], t);
    }
}

void
PG_PropagateRegToMem (PG_PROPAGATOR *pg, const uint32_t *mem_w, size_t nmem_w,
                      const uint32_t *reg_r, size_t nreg_r, void *ea)
{
  PG_TAINT_TABLE &tt = pg->tt;
  void **tea = pg->tea;

  for (size_t i = 0; i < nmem_w; ++i)
    for (size_t t = 0; t < TT_NUM_TAINT; ++t)
      if (tt.IsTainted (mem_w[i], t))
        {
          tt.UntaintCol (t);
          InvokeAddressCallbacks (&pg->address_hook[PG_AH_MARK][0],
                                  pg->address_hook[PG_AH_MARK].size (),
                                  tea[t]);
        }

  InvokeAddressCallbacks (&pg->address_hook[PG_AH_UNMARK][0],
                          pg->address_hook[PG_AH_UNMARK].size (), ea);

  // TODO: Propagate to stack memory
}

void
PG_PropagateRegClear (PG_PROPAGATOR *pg, uint32_t r)
{
  pg->tt.Diff (r, r, r);
}

void
PG_PropagateRegExchange (PG_PROPAGATOR *pg, uint32_t r1, uint32_t r2)
{
  PG_TAINT_TABLE &tt = pg->tt;
  tt.Union (TT_TMP_ROW, TT_TMP_ROW, r1);
  tt.Diff (r1, r1, r1);
  tt.Union (r1, r1, r2);
  tt.Diff (r2, r2, r2);
  tt.Union (r2, TT_TMP_ROW, TT_TMP_ROW);
  tt.Diff (TT_TMP_ROW, TT_TMP_ROW, TT_TMP_ROW);
}

size_t
PG_TaintExhaustionCount (const PG_PROPAGATOR *pg)
{
  return pg->tt.GetExhaustionCount ();
}

bool
PG_IsTainted (const PG_PROPAGATOR *pg, uint32_t r, uint32_t t)
{
  return pg->tt.IsTainted (r, t);
}
