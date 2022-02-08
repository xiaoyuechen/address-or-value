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

typedef struct Propagator Propagator;

Propagator *CreatePropagator ();

void DestroyPropagator (Propagator *pg);

void PropagateRegToReg (Propagator *pg, const uint32_t *w, size_t nw,
                        const uint32_t *r, size_t nr);

void PropagateMemToReg (Propagator *pg, const uint32_t *reg_w, size_t nreg_w,
                        const uint32_t *mem_r, size_t nmem_r, void *ea,
                        bool should_track);

void PropagateRegToMem (Propagator *pg, const uint32_t *mem_w, size_t nmem_w,
                        const uint32_t *reg_r, size_t nreg_r, void *ea);

void PropagateClear (Propagator *pg, uint32_t r);

void PropagateExchange (Propagator *pg, uint32_t r1, uint32_t r2);

size_t AddressCount (const Propagator *pg);

size_t CopyAddresses (const Propagator *pg, void **dst);

#endif
