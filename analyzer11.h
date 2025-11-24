/* analyzer.h (최종 수정본) */
#ifndef ANALYZER_H
#define ANALYZER_H

#include <stddef.h> // size_t

int get_score(const char* operation, 
              const char* new_buf, 
              const char* old_buf_or_null, 
              size_t size);

#endif // ANALYZER_H
