#include "portable_wipe.h"
#include <stdlib.h>
#include <string.h>

void *portable_wipe(void *data, size_t length) {
// simplification of: https://www.cryptologie.net/article/419/zeroing-memory-compiler-optimizations-and-memset_s/
     volatile unsigned char *p = data;
     while (length--){
         *p++ = 0;
     }
    return data;
}
