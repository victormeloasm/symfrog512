// Test-only LD_PRELOAD hook. Limit each read(2) to the number of bytes set
// in SYMFROG_READ_CHUNK to exercise stream handling under short reads.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
ssize_t read(int fd, void* buf, size_t n) {
    static ssize_t (*actual)(int,void*,size_t) = NULL;
    if (!actual) actual = (ssize_t(*)(int,void*,size_t))dlsym(RTLD_NEXT, "read");
    const char* v = getenv("SYMFROG_READ_CHUNK");
    if (v && *v) {
        unsigned long val = strtoul(v, NULL, 10);
        if (val && n>val) n=(size_t)val;
    }
    return actual(fd,buf,n);
}
