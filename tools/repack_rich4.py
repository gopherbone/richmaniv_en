#!/usr/bin/env python3
"""Repack translated English strings into rich4.exe (v2 - full pool relocation).

Approach:
  - Parse the original script pool into "#NNNN ... NUL" records (order & ids preserved).
  - Build a new pool with English text (ids unique, #NNNN prefixes kept, \\n -> 0x0A, NUL terms).
  - Non-record bytes inside the old pool range (float constants etc.) are preserved untouched;
    old record bytes are zeroed.
  - All 4-aligned pointers into the old pool VA range are rebased to the new pool.
  - UI strings rewritten in place when English fits; otherwise moved to the overflow area and
    their referencing pointers patched.
  - New PE section "ESTR" appended after .rsrc holding new pool + UI overflow.
  - A COMPAT SHIM: the old pool keeps a copy of the "#NNNN" needles? NO - unique ids everywhere
    would break needle-uniqueness (two copies of "#0000"). We DO zero old records, so lookups
    by needle find only the new pool. Only risk: direct code addressing of old pool start.
"""
import csv, struct, re, os

EXE_IN  = os.environ.get('RICH4_PLAIN_EXE', 'decrypted/plain_rich4.exe')
EXE_OUT = os.environ.get('RICH4_PATCHED_EXE', 'decrypted/rich4_en.exe')
SCRIPT_CSV = 'strings/rich4_script_strings.csv'
UI_CSV     = 'strings/rich4_ui_strings.csv'

POOL_FILE_LO = 0x6283c
POOL_FILE_HI = 0x6aa10
POOL_VA_BASE = 0x46423c
IMAGE_BASE   = 0x400000
DGROUP_RAW   = 0x61600
DGROUP_RAWSZ = 0x26c00
DGROUP_VA    = 0x463000
BSS_VA       = 0x48a000

d = bytearray(open(EXE_IN, 'rb').read())
assert len(d) == 0x93000

# ---------- 1. parse pool ----------
pool = bytes(d[POOL_FILE_LO:POOL_FILE_HI])
recs = []            # (id, start_in_pool, end_excl_nul, bytes)
pat = re.compile(rb'#(\d{4})')
pos = 0
while pos < len(pool):
    m = pat.match(pool, pos)
    if not m:
        pos += 1
        continue
    rid = int(m.group(1))
    end = pool.find(b'\x00', m.start())
    if end < 0:
        break
    recs.append((rid, m.start(), end, pool[m.start():end]))
    pos = end + 1
print(f"parsed {len(recs)} pool records")

# mask of bytes covered by records (prefix in-field NUL)
covered = bytearray(len(pool))
for rid, s, e, b in recs:
    for i in range(s, e):
        covered[i] = 1

# mark overlapping/duplicate record starts (needles appearing inside earlier records)
rec_starts = {s for _, s, _, _ in recs}

# ---------- 2. load translations ----------
ByID = {}
for row in csv.DictReader(open(SCRIPT_CSV, newline='', encoding='utf-8-sig')):
    ByID.setdefault(int(row['id']), row)


_TRANS = {0x2014: '--', 0x2013: '-', 0x2018: "'", 0x2019: "'", 0x201C: '"', 0x201D: '"',
          0x2026: '...', 0x223C: '~', 0xFF5E: '~'}
def _to_ascii(s):
    return ''.join(_TRANS.get(ord(c), c if ord(c) < 128 else '?') for c in s)

def en_of(rid, zh_bytes):
    row = ByID.get(rid)
    if row and row['english']:
        try:
            return _to_ascii(row['english'].replace('\\n', '\n')).encode('ascii')
        except Exception:
            pass
    return zh_bytes[5:]

# ---------- 3. build new pool ----------
newpool = bytearray()
seen_ids = set()
for rid, s, e, b in recs:
    if rid in seen_ids:
        # duplicate id (e.g. #0000 pattern inside another record) -> keep original text to
        # preserve lookup uniqueness: emit as its own copy anyway (lookup finds first)
        body = b[5:]
    else:
        seen_ids.add(rid)
        body = en_of(rid, b)
    newpool += ('#%04d' % rid).encode() + body + b'\x00'
print(f"new pool: {len(newpool)} bytes")

# ---------- 4. placement ----------
new_va = 0x4a6000       # after .rsrc
new_file = len(d)
rebase_delta = new_va - POOL_VA_BASE

# rebase pointers (do this BEFORE zeroing old records so pointers can be found by value;
# pointer values don't change when data bytes change)
n_rebased = 0
for off in range(0x400, DGROUP_RAW + DGROUP_RAWSZ - 4):
    v = struct.unpack_from('<I', d, off)[0]
    if POOL_VA_BASE <= v < POOL_VA_BASE + len(pool):
        struct.pack_into('<I', d, off, v + rebase_delta)
        n_rebased += 1
# also scan .text/AUTO section for pool pointers (code may push immediates)
# absolute-addressed pool pointers in code would appear as imm32 operands; rebasing them needs
# disassembly. We instead scan the whole file EXCEPT the new pool area for 4-aligned values.
for off in range(0x400, POOL_FILE_LO - 8, 4):
    v = struct.unpack_from('<I', d, off)[0]
    if POOL_VA_BASE <= v < POOL_VA_BASE + len(pool):
        struct.pack_into('<I', d, off, v + rebase_delta)
        n_rebased += 1
for off in range(POOL_FILE_HI, len(d) - 8, 4):
    v = struct.unpack_from('<I', d, off)[0]
    if POOL_VA_BASE <= v < POOL_VA_BASE + len(pool):
        struct.pack_into('<I', d, off, v + rebase_delta)
        n_rebased += 1
print(f"rebased pointers: {n_rebased}")

# zero old record bytes (skip non-record data like float constants)
n_zero = 0
for rid, s, e, b in recs:
    for i in range(s, e):
        d[POOL_FILE_LO + i] = 0
    n_zero += e - s
d[POOL_FILE_LO:POOL_FILE_LO] = d[POOL_FILE_LO:POOL_FILE_LO]  # noop keep
# ALSO zero the NULs? they're already zero.
print(f"zeroed {n_zero} old pool record bytes")

# ---------- 5. UI strings ----------
UIBySite = []
UIRows = list(csv.DictReader(open(UI_CSV, newline='', encoding='utf-8-sig')))
for r in UIRows:
    if r['kind'] != 'big5' or r.get('notes') == 'NOT_A_STRING':
        continue
    try:
        zh = r['text'].encode('big5')
    except Exception:
        continue
    site = d.find(zh)
    if site < 0 or site >= POOL_FILE_LO and site < POOL_FILE_HI:
        continue
    if not (DGROUP_RAW <= site < DGROUP_RAW + DGROUP_RAWSZ):
        # UI strings should all be in DGROUP
        continue
    UIBySite.append((site, zh, r['english']))

n_inplace = n_moved = 0
overflow = bytearray()
ui_map = []          # (old_va, new_va, old_len)
for site, zh, en in UIBySite:
    try:
        eb = _to_ascii(en.replace('\\n', '\n')).encode('ascii')
    except Exception:
        continue
    if len(eb) + 1 <= len(zh):
        d[site:site+len(zh)] = eb + b'\x00' * (len(zh) - len(eb))
        n_inplace += 1
    else:
        old_va = DGROUP_VA + (site - DGROUP_RAW)
        new_off_in_overflow = len(overflow)
        overflow += eb + b'\x00'
        new_ptr = 0x4a6000 + len(newpool) + new_off_in_overflow
        # patch all pointers to old_va
        for off in range(0x400, len(d) - 4):
            v = struct.unpack_from('<I', d, off)[0]
            if v == old_va:
                struct.pack_into('<I', d, off, new_ptr)
        d[site:site+len(zh)] = b'\x00' * len(zh)
        n_moved += 1
        ui_map.append((old_va, new_ptr, len(zh)))
print(f"UI: {n_inplace} in-place, {n_moved} relocated")

# ---------- 6. ESTR section ----------
extra = bytes(newpool) + bytes(overflow)
pe = struct.unpack_from('<I', d, 0x3c)[0]
nsec_off = pe + 6
num_sec = struct.unpack_from('<H', d, nsec_off)[0]
opt = pe + 24
sect_align = 0x1000
file_align = 0x200
vsz = ((len(extra) + sect_align - 1) // sect_align) * sect_align
rsz = ((len(extra) + file_align - 1) // file_align) * file_align
sec_tab = opt + struct.unpack_from('<H', d, pe + 20)[0]
entry = sec_tab + num_sec * 40
new_sec = bytearray(40)
new_sec[0:8] = b'ESTR\x00\x00\x00\x00'
struct.pack_into('<I', new_sec,  8, len(extra))       # VirtualSize
struct.pack_into('<I', new_sec, 12, new_va)           # VirtualAddress
struct.pack_into('<I', new_sec, 16, rsz)              # SizeOfRawData
struct.pack_into('<I', new_sec, 20, new_file)         # PointerToRawData
struct.pack_into('<I', new_sec, 36, 0xC0000040)       # data, readable
d[entry:entry+40] = new_sec
struct.pack_into('<H', d, nsec_off, num_sec + 1)
new_img = ((new_va + vsz + sect_align - 1) // sect_align) * sect_align
struct.pack_into('<I', d, opt + 56, new_img)
d += bytes(new_file + rsz - len(d))
d[new_file:new_file+len(extra)] = extra
print(f"ESTR section: VA {new_va:#x} file {new_file:#x} {len(extra)} bytes; SizeOfImage={new_img:#x}")

open(EXE_OUT, 'wb').write(bytes(d))
print(f"wrote {EXE_OUT} ({len(d)} bytes)")
