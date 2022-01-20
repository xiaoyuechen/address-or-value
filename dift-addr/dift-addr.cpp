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
#include <algorithm>
#include <fstream>
#include <iostream>
#include <map>
#include <stdio.h>
#include <types.h>

#ifndef NUM_TAINT
#define NUM_TAINT 16
#endif

#ifndef MAX_OP_COUNT
#define MAX_OP_COUNT 16
#endif

using std::cerr;
using std::endl;
using std::string;

#define OP_T_LIST                                                             \
  X0 (NONE)                                                                   \
  X (IMM)                                                                     \
  X (REG)                                                                     \
  X (MEM)                                                                     \
  X (ADR)

typedef enum
{
#define X(name) OP_T_##name,
#define X0(name) X (name)
  OP_T_LIST
#undef X0
#undef X
      OP_T_COUNT
} OP_T;

static const char *OP_T_STR[OP_T_COUNT] = {
#define X(name) #name,
#define X0(name) "---",
  OP_T_LIST
#undef X0
#undef X
};

typedef enum
{
  OP_RW_NONE = 0,
  OP_RW_R = 1 << 0,
  OP_RW_W = 1 << 1
} OP_RW;

typedef struct OP
{
  OP_T t;
  OP_RW rw;

  union CONTENT
  {
    REG reg;
    struct MEM
    {
      REG base, index;
    } mem;
  } content;
} OP;

string
OP_ToString (OP op)
{
  static const size_t MAX_CHAR_COUNT = 64;
  char buff[MAX_CHAR_COUNT];
  int offset = snprintf (buff, MAX_CHAR_COUNT, "%s %d%d ", OP_T_STR[op.t],
                         op.rw & OP_RW_R ? 1 : 0, op.rw & OP_RW_W ? 1 : 0);
  switch (op.t)
    {
    case OP_T_REG:
      snprintf (buff + offset, MAX_CHAR_COUNT, "%s",
                REG_StringShort (op.content.reg).c_str ());
      break;
    case OP_T_MEM:
    case OP_T_ADR:
      snprintf (buff + offset, MAX_CHAR_COUNT, "%s %s",
                REG_valid (op.content.mem.base)
                    ? REG_StringShort (op.content.mem.base).c_str ()
                    : "",
                REG_valid (op.content.mem.index)
                    ? REG_StringShort (op.content.mem.index).c_str ()
                    : "");
      break;
    case OP_T_IMM:
    default:
      break;
    }

  return string (buff);
}

OP_T
OP_Type (INS ins, UINT32 n)
{
  return INS_OperandIsImmediate (ins, n)          ? OP_T_IMM
         : INS_OperandIsReg (ins, n)              ? OP_T_REG
         : INS_OperandIsMemory (ins, n)           ? OP_T_MEM
         : INS_OperandIsAddressGenerator (ins, n) ? OP_T_ADR
                                                  : OP_T_NONE;
}

/* ================================================================== */
// Global variables
/* ================================================================== */

static std::map<ADDRINT, string> disassemble;
static da::TAINT_TABLE<REG_GR_LAST, NUM_TAINT> taint_table;
// static ADDRINT *ea[NUM_TAINT];

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

int
INS_Operands (INS ins, OP *op)
{
  for (UINT32 n = 0; n < INS_OperandCount (ins); ++n)
    {
      op[n].t = OP_Type (ins, n);
      op[n].rw
          = (OP_RW)((INS_OperandRead (ins, n) ? OP_RW_R : OP_RW_NONE)
                    | (INS_OperandWritten (ins, n) ? OP_RW_W : OP_RW_NONE));
      switch (op[n].t)
        {
        case OP_T_REG:
          op[n].content.reg = INS_OperandReg (ins, n);
          break;
        case OP_T_MEM:
        case OP_T_ADR:
          op[n].content.mem.base = INS_MemoryBaseReg (ins);
          op[n].content.mem.index = INS_MemoryIndexReg (ins);
        case OP_T_IMM:
        default:
          break;
        }
    }
  return INS_OperandCount (ins);
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
OnMemoryRead (REG dest, REG src, REG base, REG index, ADDRINT *ea)
{
  printf ("dest=%s src=%s base=%s index=%s\nea=%p\n",
          REG_StringShort (dest).c_str (), REG_StringShort (src).c_str (),
          REG_StringShort (base).c_str (), REG_StringShort (index).c_str (),
          ea);
}

/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

VOID
OpInfo (INS ins)
{
  OP op[MAX_OP_COUNT];
  int nop = INS_Operands (ins, op);
  for (int i = 0; i < nop; ++i)
    {
      printf ("    OP %d: %s\n", i + 1, OP_ToString (op[i]).c_str ());
    }
}

VOID
Trace (INS ins, VOID *v)
{
  disassemble[INS_Address (ins)] = INS_Disassemble (ins);
  Disassemble (INS_Address (ins));
  // INS_InsertCall (ins, IPOINT_BEFORE, (AFUNPTR)Disassemble, IARG_ADDRINT,
  //                 INS_Address (ins), IARG_END);
  OpInfo (ins);
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
  INS_AddInstrumentFunction (Trace, 0);

  // Register function to be called when the application exits
  PIN_AddFiniFunction (Fini, 0);

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
