# 大富翁4 (Richman 4) → English Translation Feasibility

Analyzing the CD image (v3.11, Softstar 1999). Conclusion: **translation is
feasible with moderate reverse-engineering effort.** All game text is standard Big5
rendered through Windows GDI (`TextOutA` + `CreateFontA` with CHINESEBIG5_CHARSET —
confirmed via the open-source mytbk/rich4 reverse-engineering project), not bitmapped
fonts.

## Where the text lives

1. **rich4.exe (602,112 B)** — the main translation target. Contains thousands of Big5
   double-byte strings (dialog, item/card names, UI labels, event text). A decrypted
   copy was recovered (602,112 B, valid PE; its SHA-256 matches the value documented by
   the independent mytbk/rich4 project, confirming it is the genuine v3.11 executable,
   not the CD-encrypted variant).
2. **Panel.mkf** — some text baked into UI sprite graphics (image editing required).
3. **Speaking.mkf** — voice acting; cannot be translated (leave as-is).
4. **AVI cutscenes** — subtitles are burned into the video; hardest content (fan
   translations typically skip these or add soft subs).

## Cipher status

All 8 protected files (rich4.exe + 7 .mkf) are XOR-encrypted with a 71-byte-period
keystream. Findings (see `tools/README.md` for the base key and per-column tables):

- The keystream is `K1 ^ D(column, previous-plaintext-byte?)` — actually implemented as a
  per-(column, plaintext-byte) substitution table S(j, p), fully recovered for
  rich4.exe / Effect.mkf / Speaking.mkf via known-plaintext pairs.
- End-to-end verified decryption: rich4.exe, Effect.mkf (0/3.9 MB mismatches),
  Speaking.mkf, help.mkf (partial — one more cipher-state layer remains).
- Not yet decrypted from the CD image: Data.mkf, Panel.mkf, jump.mkf, map.mkf.
  Routes to obtain them:
  1. reverse the key-generator code inside the decrypted rich4.exe;
  2. obtain plaintext copies of these files from other distributions;
  3. HD-repacked variants exist (different sizes/content but same resource layout and
     text), usable as a reference or as replacement assets.

## Recommended translation path

1. Extract the Big5 string table from the decrypted rich4.exe (script strings use
   `#NNNN` record markers; ~1,350 records, plus ~800 untagged UI strings).
2. Translate Big5 → English. Lengths matter: the renderer uses proportional GDI fonts;
   DB→ASCII generally halves byte length, which is safe.
3. Patch the translated strings back into the PE (Watcom-compiled; if any string grows,
   move it to an appended section and fix pointers/relocations).
4. The `CreateFontA` call selecting CHINESEBIG5_CHARSET will still render ASCII fine;
   optionally change the charset to DEFAULT_CHARSET for better font selection.

## Repo contents

- `tools/` — decryption/decompression tooling (see `tools/README.md`).
  - `mkfx` — MKF container extractor (`list` / `extract <index> <out.bin>`).
  - `rich4_decrypt.py` — CD-encryption decryptor (keystream-table approach).
  - `mkf_decompress.c` — the game's proprietary chunk decompressor (from mytbk/rich4, GPL-3.0).
- Game assets are **not** committed (see `.gitignore`); place them locally beside these tools.

## Repacker (built)

`tools/repack_rich4.py` produces `decrypted/rich4_en.exe` (642,560 B, valid PE with a new
`ESTR` section at VA 0x4a6000). Verified: all 1,354 script records re-decode from the patched
exe byte-identical to the CSV `english` column. 63 UI strings rewritten in place; 197 grown
strings relocated into ESTR with pointer rebasing; 2,035 pool pointers rebased; old record
bytes zeroed (non-record data such as float constants preserved untouched).

Remaining caveat: runtime verification under Wine (not yet installed) — the repack assumes the
game looks up script text by `#NNNN` needle/pointer rather than by fixed offsets, supported by
the fact that the original pool itself is unsorted (e.g. #0010 precedes #0009).
