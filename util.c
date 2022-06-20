#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <err.h>


void
hexdump(const char *buf, int buf_len)
{
    int i;
    printf("%08x ", 0);
    for (i = 0; i < buf_len; ++i)
    {
	if (i % 16 == 0 && i)
	{
	    printf("  ");
	    for (int j = 16; j; --j)
		printf("%c", isprint(buf[i-j]) ? buf[i-j] : '.');
	    printf("\n%08x ", i);
	}
	printf(" %02hhx", buf[i]);
    }
    if (i % 16)
    {
	printf("%*s", (16-i%16)*3 + 2, "");
	for (int j = i % 16; j; --j)
	    printf("%c", isprint(buf[i-j]) ? buf[i-j] : '.');
	puts("");
	printf("%08x\n", i);
    }
    puts("");
}

char**
read_n_lines(int n, FILE* file, int discard)
{
    char **result;
    size_t str_size = 0, ind;
    if (!discard)
	result = calloc(n, sizeof(char*));
    
    for (int i = 0; i < n; ++i)
    {
	if (discard)
	    ind = 0;
	else
	    ind = i;
	if (getline(&result[ind], &str_size, file) == -1)
	{
	    warnx("Can't read line from file");
	    break;
	}
    }
    
    if (discard)
	return NULL;
    return result;
}

void
newline_flush(FILE *file)
{
    int c;
    do
    {
	c = getc(file);
    } while (c != '\n');
}

void
log_message(FILE *file, const char *format,...)
{
    va_list vl;
    va_start(vl, format);
    fprintf(file, "[*]   ");
    vfprintf(file, format, vl);
    fprintf(file, "\n");
    va_end(vl);
}
