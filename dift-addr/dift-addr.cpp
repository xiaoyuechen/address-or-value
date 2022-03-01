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

#include "pin.H" /* pin.H must be included first */

#include "instlib.H"
#include "instrument-propagation.h"
#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <map>

#ifndef NUM_TAINT
#define NUM_TAINT 16
#endif

using std::string;

INSTLIB::FILTER filter;

FILE *out = stderr;

KNOB<string> KnobOutputFile (KNOB_MODE_WRITEONCE, "pintool", "o",
                             "dift-addr.out",
                             "The output file name for dift-addr");

KNOB<size_t> KnobWarmupIns (
    KNOB_MODE_WRITEONCE, "pintool", "warmup", "0",
    "Do not dump before WARMUP number of instructions have been executed");

KNOB<size_t> KnobDumpPeriod (KNOB_MODE_WRITEONCE, "pintool", "dumpperiod", "1",
                             "Dump every DUMPPERIOD instructions");

int
Usage ()
{
  fprintf (stderr, "%s%s\n",
           "This tool prints out the addresses that contains addresses\n",
           KNOB_BASE::StringKnobSummary ().c_str ());
  return -1;
}

void
Banner ()
{
  fprintf (stderr, "===============================================\n"
                   "This application is instrumented by dift-addr\n");
  if (!KnobOutputFile.Value ().empty ())
    {
      fprintf (stderr, "See file %s for analysis results\n",
               KnobOutputFile.Value ().c_str ());
    }
  fprintf (stderr, "===============================================\n");
}

void
Init (int argc, char *argv[])
{
  if (PIN_Init (argc, argv))
    exit (Usage ());

  Banner ();

  PIN_InitSymbols ();

  out = KnobOutputFile.Value ().empty ()
            ? stderr
            : fopen (KnobOutputFile.Value ().c_str (), "w");

  filter.Activate ();

  PG_Init ();
  PG_SetDumpFile (out);
  PG_SetWarmup (KnobWarmupIns.Value ());
  PG_SetDumpPeriod (KnobDumpPeriod.Value ());
  PG_DumpHeader ();
}

void
Trace (TRACE trace, void *val)
{
  if (!filter.SelectTrace (trace))
    return;

  for (BBL bbl = TRACE_BblHead (trace); BBL_Valid (bbl); bbl = BBL_Next (bbl))
    {
      for (INS ins = BBL_InsHead (bbl); INS_Valid (ins); ins = INS_Next (ins))
        {
          PG_InstrumentPropagation (ins);
        }
    }
}

void
ImgLoad (IMG img, void *)
{
  fprintf (stderr, "%s load offset: %p\n", IMG_Name (img).c_str (),
           (void *)IMG_LoadOffset (img));
}

void
Fini (INT32 code, void *v)
{
  PG_Fini ();
  fclose (out);
}

int
main (int argc, char *argv[])
{
  Init (argc, argv);

  TRACE_AddInstrumentFunction (Trace, 0);
  /* IMG_AddInstrumentFunction (ImgLoad, 0); */
  PIN_AddFiniFunction (Fini, 0);

  PIN_StartProgram ();

  return 0;
}
