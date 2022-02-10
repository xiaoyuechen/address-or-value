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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifndef TT_NUM_ROW
#define TT_NUM_ROW 32
#endif

#ifndef TT_NUM_TAINT
#define TT_NUM_TAINT 32
#endif

typedef struct PG_PROPAGATOR PG_PROPAGATOR;

typedef void (*PG_ADDRESS_HOOK_FN) (void *ea, void *user_ptr);

PG_PROPAGATOR *PG_CreatePropagator ();

void PG_DestroyPropagator (PG_PROPAGATOR *pg);

void PG_AddToAddressMarkHook (PG_PROPAGATOR *pg, PG_ADDRESS_HOOK_FN fn, void* user_ptr);

void PG_AddToAddressUnmarkHook (PG_PROPAGATOR *pg, PG_ADDRESS_HOOK_FN fn, void* user_ptr);

void PG_PropagateRegToReg (PG_PROPAGATOR *pg, const uint32_t *w, size_t nw,
                           const uint32_t *r, size_t nr);

void PG_PropagateMemToReg (PG_PROPAGATOR *pg, const uint32_t *reg_w,
                           size_t nreg_w, const uint32_t *mem_r, size_t nmem_r,
                           void *ea);

void PG_PropagateRegToMem (PG_PROPAGATOR *pg, const uint32_t *mem_w,
                           size_t nmem_w, const uint32_t *reg_r, size_t nreg_r,
                           void *ea);

void PG_PropagateRegClear (PG_PROPAGATOR *pg, uint32_t r);

void PG_PropagateRegExchange (PG_PROPAGATOR *pg, uint32_t r1, uint32_t r2);

size_t PG_TaintExhaustionCount (const PG_PROPAGATOR *pg);

bool PG_IsTainted (const PG_PROPAGATOR *pg, uint32_t r, uint32_t t);

#endif
