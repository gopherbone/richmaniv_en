# Richman 4 (大富翁4) CD decryption & resource tools

Findings summary (see analysis session for details):

## Encryption
All 8 protected files on the CD (rich4.exe + 7 .mkf) are XOR-encrypted with a 71-byte-period
keystream. Observations:

- Base key K1 (constant across files, phase 0 = file start):
  d5 d1 dd d9 c5 c1 cd c9 f5 f1 fd f9 e5 e1 ed e9 95 91 9d 99 85 81 8d 89
  b5 b1 bd b9 a5 a1 ad a9 55 51 5d 59 45 41 4d 49 75 71 7d 79 65 61 6d 69
  15 11 1d 19 05 01 0d 09 35 31 3d 39 25 21 2d 29 d4 d0 dc d8 c4 c0 cc
- The keystream is not plain K1: it is K1 ^ D(j, p) where D is a GF(2)-linear function of the
  PLAINTEXT byte p and column j = i % 71. D was fully recovered as an empirical 71x256 byte table
  (see rich4_decrypt.py / val_exe.py lineage), verified to decrypt:

    * rich4.exe  (pair: plaintext from HD-Mac repo)  - mismatches only in 22 cells
    * Effect.mkf - 0 mismatches over 3.9 MB
    * Speaking.mkf - 0 mismatches
    * help.mkf - 46% mismatch: D depends on extra state in this file's case (unresolved)

- Per-column collision kernels (e.g. col0: p, p^0x55, p^0xaa, p^0xff give same ciphertext) mean the
  cipher is 4-to-1 in those cells; decryption of unluckily-colliding bytes needs decompression
  context (impossible standalone).

- NOT yet decryption-verified: Data.mkf, Panel.mkf, jump.mkf, map.mkf from this ISO. Their
  keystream does not match S(j,p) (likely one more evolution layer). Sounds/graphic content is
  recoverable via:
    1. reverse the key-generator code in rich4.exe (plain PE available), or
    2. obtain plaintext copies (HD-Mac repo ships Data/Panel/jump/map but HD-repacked:
       different sizes/content), or
    3. install the game under Wine and dump files (the CD version here is a "crack.EXE"-present
       pirated variant whose files may differ from a retail install).

## Tools

- mkf_decompress.c : the game's chunk decompressor (reverse-engineered by mytbk/rich4 project,
  GPL-3.0; tables correspond to addresses in rich4.exe).
- mkfx.c           : quick MKF container tool. Usage:
    ./mkfx <file.mkf> list
    ./mkfx <file.mkf> extract <index> <out.bin>
  Build: cc -O2 -o mkfx mkfx.c mkf_decompress.c
- rich4_decrypt.py : python decryptor implementing the recovered S(j,p) keystream table.
- rich4_tool.c     : suffix-array longest-repeated-substring finder (crack methodology).

## MKF format (per mytbk/rich4 docs)
- dword[0] at file start: offset of the index table (last dword array = chunk start offsets).
- Each chunk: [uncomp_size][comp_size][gfx_data_off][gfx_data_size] then comp_size bytes
  (comp_size == uncomp_size => stored raw, else decompress with mkf_decompress).
- SPR/SMP chunks contain sub-chunk tables (see csrc/mkf/mkf-format.md in mytbk/rich4).

## Plain copies obtained (from gnuhpc/Richman-4-HD-Mac)
- rich4.exe v3.11 (602112 B, exact size match; MZ PE)  - all game strings live here (Big5, GDI TextOutA)
- Effect.mkf, Speaking.mkf, help.mkf (byte-size matches to the CD copies)
