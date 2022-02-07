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

#include "operand.hpp"
#include "propagation.hpp"
#include "taint-table.hpp"
#include "types_foundation.PH"
#include "types_vmapi.PH"
#include "util.hpp"
#include <algorithm>
#include <fstream>
#include <iostream>
#include <map>
#include <stdio.h>
#include <types.h>

#ifndef NUM_TAINT
#define NUM_TAINT 16
#endif

using std::cerr;
using std::endl;
using std::string;

/* ================================================================== */
// Global variables
/* ================================================================== */

INSTLIB::FILTER filter;

std::ostream *out = &cerr;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<string> KnobOutputFile (KNOB_MODE_WRITEONCE, "pintool", "o", "",
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
  cerr << "This tool prints out the number of dynamically executed " << endl
       << "instructions, basic blocks and threads in the application." << endl
       << endl;

  cerr << KNOB_BASE::StringKnobSummary () << endl;
  return -1;
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
  *out << "===============================================" << endl;
  *out << "dift-addr analysis results: " << endl;
  *out << "===============================================" << endl;
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
  PIN_InitSymbols ();
  // Initialize PIN library. Print help message if -h(elp) is specified
  // in the command line or the command line is invalid
  if (PIN_Init (argc, argv))
    {
      return Usage ();
    }

  string file_name = KnobOutputFile.Value ();

  if (!file_name.empty ())
    {
      out = new std::ofstream (file_name.c_str ());
    }

  // Register function to be called to instrument traces
  // RTN_AddInstrumentFunction (TraceRoutine, 0);
  TRACE_AddInstrumentFunction (Trace, 0);
  filter.Activate ();

  // Register function to be called when the application exits
  PIN_AddFiniFunction (Fini, 0);
  PIN_AddFiniFunction (PG_Fini, 0);

  cerr << "===============================================" << endl;
  cerr << "This application is instrumented by dift-addr" << endl;
  if (!KnobOutputFile.Value ().empty ())
    {
      cerr << "See file " << KnobOutputFile.Value () << " for analysis results"
           << endl;
    }
  cerr << "===============================================" << endl;

  // Start the program, never returns
  PIN_StartProgram ();

  return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
