#ifndef UTIL_H
#define UTIL_H

#include "pin.H"
#include "types_core.PH"
#include <string>

const char *UT_StripPath (const char *path);
std::string UT_InsOpString (INS ins);
std::string UT_InsRtnString (INS ins, RTN rtn);

#endif
