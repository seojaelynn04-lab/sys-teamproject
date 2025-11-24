#ifndef ANALYZER_H
#define ANALYZER_H
#include <stddef.h>

int get_score(const char* operation, const char* new_buf, const char* old_buf_or_null, size_t size);
#endif
