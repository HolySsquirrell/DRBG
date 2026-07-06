#include <stdio.h>
#include <stdarg.h>

#include "logger.h"

static void log_message(
    const char *prefix,
    const char *fmt,
    va_list args)
{
    printf("%s ", prefix);
    vprintf(fmt, args);
    printf("\n");
}

void log_info(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    log_message("[INFO]", fmt, args);
    va_end(args);
}

void log_success(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    log_message("[ OK ]", fmt, args);
    va_end(args);
}

void log_warning(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    log_message("[WARN]", fmt, args);
    va_end(args);
}

void log_error(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    log_message("[FAIL]", fmt, args);
    va_end(args);
}