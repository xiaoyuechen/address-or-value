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

#include "pin.H"
// pin.H must be included first
#include "instlib.H"

#include "instrument-propagation.h"
#include "types_foundation.PH"
#include "types_vmapi.PH"
#include "util.hpp"
#include <algorithm>
#include <cstdio>
#include <map>
#include <types.h>

#ifndef NUM_TAINT
#define NUM_TAINT 16
#endif

using std::string;

/* ================================================================== */
// Global variables
/* ================================================================== */

INSTLIB::FILTER filter;

FILE *out = stderr;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<string> KnobOutputFile (KNOB_MODE_WRITEONCE, "pintool", "o",
                             "dift-addr.out",
                             "specify file name for dift-addr output");

/* ===================================================================== */
// Utilities
/* ===================================================================== */

/*!
 *  Print out help message.
 */
INT32
Usage ()
{
  fprintf (stderr, "%s%s\n",
           "This tool prints out the addresses that contains addresses\n",
           KNOB_BASE::StringKnobSummary ().c_str ());
  return -1;
}

VOID
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

VOID
Init (int argc, char *argv[])
{
  PIN_InitSymbols ();
  if (PIN_Init (argc, argv))
    {
      exit (Usage ());
    }

  string file_name = KnobOutputFile.Value ();
  if (!file_name.empty ())
    {
      out = fopen (file_name.c_str (), "w");
    }

  filter.Activate ();

  PG_Init (out);
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

VOID
Trace (TRACE trace, VOID *val)
{
  if (!filter.SelectTrace (trace))
    return;

  for (BBL bbl = TRACE_BblHead (trace); BBL_Valid (bbl); bbl = BBL_Next (bbl))
    {
      for (INS ins = BBL_InsHead (bbl); INS_Valid (ins); ins = INS_Next (ins))
        {
          PG_InstrumentPropagation (ins);
          // printf ("%s", UT_InsOpString (ins).c_str ());
          // printf ("%s", UT_InsRtnString (ins, TRACE_Rtn (trace)).c_str ());
        }
    }
}

/*!
 * Print out analysis results.
 * This function is called when the application exits.
 * @param[in]   code            exit code of the application
 * @param[in]   v               value specified by the tool in the
 *                              PIN_AddFiniFunction function call
 */
VOID
Fini (INT32 code, VOID *v)
{
  fprintf (out, "===============================================\n"
                "dift-addr analysis results:\n"
                "===============================================\n");
  PG_Fini ();
  fclose (out);
}

/*!
 * The main procedure of the tool.
 * This function is called when the application image is loaded but not yet
 * started.
 * @param[in]   argc            total number of elements in the argv array
 * @param[in]   argv            array of command line arguments,
 *                              including pin -t <toolname> -- ...
 */
int
main (int argc, char *argv[])
{
  Init (argc, argv);

  TRACE_AddInstrumentFunction (Trace, 0);
  PIN_AddFiniFunction (Fini, 0);

  Banner ();
  PIN_StartProgram ();

  return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
