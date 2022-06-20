#ifndef UTIL_H_INCLUDED_
#define UTIL_H_INCLUDED_

#include <stdio.h>

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)  /* Converts macro name to C-string */

void
__attribute__((weak))
hexdump(const char* data, int num_bytes);   /* Prints hexdump of data */

char**
__attribute__((weak))
read_n_lines(int n, FILE* file, int discard); /* Reads n lines from file */

void
__attribute__((weak))
newline_flush(FILE *file); /* Flushes until and including newline */

void
__attribute__((weak))
log_message(FILE *file, const char *format,...);

#endif /*UTIL_H_INCLUDED_*/
