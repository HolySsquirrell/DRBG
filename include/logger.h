#ifndef LOGGER_H
#define LOGGER_H

void log_info(const char *fmt, ...);

void log_success(const char *fmt, ...);

void log_warning(const char *fmt, ...);

void log_error(const char *fmt, ...);

#endif