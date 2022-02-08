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

#ifndef PROPAGATION_H
#define PROPAGATION_H

#include <stddef.h>
#include <stdint.h>

#ifndef TT_NUM_ROW
#define TT_NUM_ROW 32
#endif

#ifndef TT_NUM_TAINT
#define TT_NUM_TAINT 16
#endif

typedef struct PG_Propagator PG_Propagator;

PG_Propagator *PG_CreatePropagator ();

void PG_DestroyPropagator (PG_Propagator *pg);

void PG_PropagateRegToReg (PG_Propagator *pg, const uint32_t *w, size_t nw,
                           const uint32_t *r, size_t nr);

void PG_PropagateMemToReg (PG_Propagator *pg, const uint32_t *reg_w,
                           size_t nreg_w, const uint32_t *mem_r, size_t nmem_r,
                           void *ea, bool should_track);

void PG_PropagateRegToMem (PG_Propagator *pg, const uint32_t *mem_w,
                           size_t nmem_w, const uint32_t *reg_r, size_t nreg_r,
                           void *ea);

void PG_PropagateRegClear (PG_Propagator *pg, uint32_t r);

void PG_PropagateRegExchange (PG_Propagator *pg, uint32_t r1, uint32_t r2);

size_t PG_AddressCount (const PG_Propagator *pg);

size_t PG_CopyAddresses (const PG_Propagator *pg, void **dst);

size_t PG_TaintExhaustionCount (const PG_Propagator *pg);

#endif
