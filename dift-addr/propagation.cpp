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
#include <set>

static constexpr size_t TT_TMP_ROW = TT_NUM_ROW + 1;
using PG_TAINT_TABLE = TAINT_TABLE<TT_TMP_ROW + 1, TT_NUM_TAINT>;
using PG_ADDR_SET = std::set<void *>;

struct PG_Propagator
{
  PG_TAINT_TABLE tt{};
  void *tea[TT_NUM_TAINT] = {};
  PG_ADDR_SET addr_set{};
};

PG_Propagator *
PG_CreatePropagator ()
{
  return new PG_Propagator{};
}

void
PG_DestroyPropagator (PG_Propagator *pg)
{
  delete pg;
}

void
PG_PropagateRegToReg (PG_Propagator *pg, const uint32_t *w, size_t nw,
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
PG_PropagateMemToReg (PG_Propagator *pg, const uint32_t *reg_w, size_t nreg_w,
                      const uint32_t *mem_r, size_t nmem_r, void *ea,
                      bool should_track)
{
  PG_TAINT_TABLE &tt = pg->tt;
  PG_ADDR_SET &addr_set = pg->addr_set;
  void **tea = pg->tea;

  for (size_t i = 0; i < nmem_r; ++i)
    for (size_t t = 0; t < TT_NUM_TAINT; ++t)
      if (tt.IsTainted (mem_r[i], t))
        {
          tt.UntaintCol (t);
          addr_set.insert (tea[t]);
        }

  for (size_t i = 0; i < nreg_w; ++i)
    {
      tt.Diff (reg_w[i], reg_w[i], reg_w[i]);
    }

  if (should_track)
    {
      size_t t = tt.NextAvailableTaint ();
      tea[t] = ea;
      for (size_t i = 0; i < nreg_w; ++i)
        {
          tt.Taint (reg_w[i], t);
        }
    }
}

void
PG_PropagateRegToMem (PG_Propagator *pg, const uint32_t *mem_w, size_t nmem_w,
                      const uint32_t *reg_r, size_t nreg_r, void *ea)
{
  PG_TAINT_TABLE &tt = pg->tt;
  PG_ADDR_SET &addr_set = pg->addr_set;
  void **tea = pg->tea;

  for (size_t i = 0; i < nmem_w; ++i)
    for (size_t t = 0; t < TT_NUM_TAINT; ++t)
      if (tt.IsTainted (mem_w[i], t))
        {
          tt.UntaintCol (t);
          addr_set.insert (tea[t]);
        }

  addr_set.erase (ea);

  // TODO: Propagate to stack memory
}

void
PG_PropagateRegClear (PG_Propagator *pg, uint32_t r)
{
  pg->tt.Diff (r, r, r);
}

void
PG_PropagateRegExchange (PG_Propagator *pg, uint32_t r1, uint32_t r2)
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
PG_AddressCount (const PG_Propagator *pg)
{
  return pg->addr_set.size ();
}

size_t
PG_CopyAddresses (const PG_Propagator *pg, void **dst)
{
  std::copy (pg->addr_set.begin (), pg->addr_set.end (), dst);
  return pg->addr_set.size ();
}

size_t
PG_TaintExhaustionCount (const PG_Propagator *pg)
{
  return pg->tt.GetExhaustionCount ();
}
