#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
void mkf_decompress(void *arg1, const void *src, size_t buf_size);
int main(int argc, char**argv){
    // argv[1]=file, argv[2]=cmd(list|extract), argv[3]=index, argv[4]=outfile
    FILE*f=fopen(argv[1],"rb");
    if(!f){perror("open");return 1;}
    fseek(f,0,SEEK_END); long sz=ftell(f); fseek(f,0,SEEK_SET);
    uint8_t*buf=malloc(sz); fread(buf,1,sz,f); fclose(f);
    uint32_t idx_off; memcpy(&idx_off, buf, 4);
    long nchunk = ((long)sz - idx_off) / 4;
    uint32_t *idx = (uint32_t*)(buf + idx_off);
    int extract = strcmp(argv[2],"extract")==0;
    int target = extract ? atoi(argv[3]) : -1;
    for (long c=0; c<nchunk; c++) {
        uint32_t off = idx[c];
        if (off >= (uint32_t)sz) continue;
        uint32_t meta[4]; memcpy(meta, buf+off, 16);
        if (!extract) {
            printf("chunk %ld: off=0x%08x real=%u comp=%u goff=%u gsize=%u\n",
                   c, off, meta[0], meta[1], meta[2], meta[3]);
        } else if ((long)c == target) {
            uint8_t *src = buf + off + 16;
            uint8_t *out = calloc(meta[0] + 16, 1);
            if (meta[1] == meta[0]) {
                memcpy(out, src, meta[0]);
            } else {
                mkf_decompress(out, src, meta[1]);
            }
            FILE*g=fopen(argv[4],"wb"); fwrite(out,1,meta[0],g); fclose(g);
            printf("extracted chunk %ld -> %s (%u bytes)\n", c, argv[4], meta[0]);
            return 0;
        }
    }
    if (!extract) printf("total chunks: %ld\n", nchunk);
    return 0;
}
