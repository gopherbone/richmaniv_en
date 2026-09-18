// rich4_tool: analyze periodicity of rich4.exe-style encrypted files
// usage: rich4_tool <file>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static unsigned char *gb;
static long gn;
static int suffix_cmp(const void *A, const void *B) {
    long i = *(const long *)A, j = *(const long *)B;
    const unsigned char *x = gb + i, *y = gb + j;
    long li = gn - i, lj = gn - j;
    long l = li < lj ? li : lj;
    for (long k = 0; k < l; k++) {
        if (x[k] != y[k]) return x[k] < y[k] ? -1 : 1;
    }
    return li < lj ? -1 : (li > lj ? 1 : 0);
}

static unsigned char *load(const char *path, long *sizep) {
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", path); exit(1); }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *buf = malloc(sz);
    if (!buf) { fprintf(stderr, "oom\n"); exit(1); }
    if (fread(buf, 1, sz, f) != (size_t)sz) { fprintf(stderr, "short read\n"); exit(1); }
    fclose(f);
    *sizep = sz;
    return buf;
}

int main(int argc, char **argv) {
    long sz;
    unsigned char *b = load(argv[1], &sz);
    printf("file size: %ld (0x%lx)\n", sz, sz);

    // Search for long repeated substrings via qsort of suffixes (SA approach)
    // Use a simple approach: build suffix array with qsort, compute LCP with neighbors.
    long n = sz;
    gb = b; gn = n;
    long *sa = malloc((n + 1) * sizeof(long));
    if (!sa) { fprintf(stderr, "oom sa\n"); return 1; }
    for (long i = 0; i < n; i++) sa[i] = i;

    // qsort suffixes: comparator compares suffixes
    // (slow for big files but fine for ~600KB)
    qsort(sa, n, sizeof(long), suffix_cmp);

    // LCP between adjacent suffixes using memcmp trick (bounded)
    long best = 0, besti = 0, bestj = 0;
    for (long k = 0; k + 1 < n; k++) {
        long i = sa[k], j = sa[k + 1];
        long li = n - i, lj = n - j;
        long l = li < lj ? li : lj;
        // binary search LCP with memcmp
        long lo = 0, hi = l;
        while (lo < hi) {
            long mid = (lo + hi + 1) / 2;
            if (memcmp(b + i, b + j, mid) == 0) lo = mid; else hi = mid - 1;
        }
        if (lo > 64 && lo > best) { best = lo; besti = i; bestj = j; }
    }
    printf("longest repeated substring: length %ld at offsets %ld and %ld\n", best, besti, bestj);
    if (best > 0) {
        printf("  delta between offsets: %ld\n", labs(besti - bestj));
    }
    return 0;
}
