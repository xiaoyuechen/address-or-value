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
#include "taint-table.h"
#include "types_foundation.PH"
#include "types_vmapi.PH"
#include <fstream>
#include <iostream>
#include <map>
#include <stdio.h>
#include <types.h>

#ifndef MAX_TAINT_SET_SIZE
#define MAX_TAINT_SET_SIZE 8
#endif

#ifndef MAX_REG_ARRAY_SIZE
#define MAX_REG_ARRAY_SIZE 2
#endif

using std::cerr;
using std::endl;
using std::string;

/* ================================================================== */
// Global variables
/* ================================================================== */

static std::map<ADDRINT, string> disassemble;

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

VOID
MemoryReadInfo (INS ins, REG *dst, REG *base, REG *idx)
{
  *dst = REG_INVALID ();
  for (UINT32 op = 0; op < INS_OperandCount (ins); ++op)
    {
      if (INS_OperandWritten (ins, op) && INS_OperandIsReg (ins, op))
        {
          REG reg = INS_OperandReg (ins, op);
          if (REG_is_gr (reg))
            {
              *dst = reg;
            }
        }
    }

  *base = INS_MemoryBaseReg (ins);
  *idx = INS_MemoryIndexReg (ins);
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

VOID
Disassemble (ADDRINT addr)
{
  printf ("%s\n", disassemble[addr].c_str ());
}

VOID
OnMemoryRead (REG dest, REG base, REG index, ADDRINT *ea)
{
  printf ("dest=%s base=%s index=%s\nea=%p\n", REG_StringShort (dest).c_str (),
          REG_StringShort (base).c_str (), REG_StringShort (index).c_str (),
          ea);
}

/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

VOID
TraceMemoryRead (INS ins)
{
  if (INS_IsMemoryRead (ins))
    {
      disassemble[INS_Address (ins)] = INS_Disassemble (ins);
      INS_InsertCall (ins, IPOINT_BEFORE, (AFUNPTR)Disassemble, IARG_ADDRINT,
                      INS_Address (ins), IARG_END);

      REG dest, base, index;
      MemoryReadInfo (ins, &dest, &base, &index);
      INS_InsertCall (ins, IPOINT_BEFORE, (AFUNPTR)OnMemoryRead, IARG_UINT32,
                      dest, IARG_UINT32, base, IARG_UINT32, index,
                      IARG_MEMORYREAD_EA, IARG_END);
    }
}

VOID
Trace (INS ins, VOID *v)
{
  if (INS_IsMemoryRead (ins))
    {
      TraceMemoryRead (ins);
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
  *out << "dift-tool analysis results: " << endl;
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
  // Initialize PIN library. Print help message if -h(elp) is specified
  // in the command line or the command line is invalid
  if (PIN_Init (argc, argv))
    {
      return Usage ();
    }

  TAINT_TABLE<16, 32> tt;
  tt.IsTainted(0, 0);
  tt.IsTainted(0, 0);

  string file_name = KnobOutputFile.Value ();

  if (!file_name.empty ())
    {
      out = new std::ofstream (file_name.c_str ());
    }

  // Register function to be called to instrument traces
  INS_AddInstrumentFunction (Trace, 0);

  // Register function to be called when the application exits
  PIN_AddFiniFunction (Fini, 0);

  cerr << "===============================================" << endl;
  cerr << "This application is instrumented by dift-tool" << endl;
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
