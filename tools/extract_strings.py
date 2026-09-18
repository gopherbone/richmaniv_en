#!/usr/bin/env python3
"""Extract the Big5 string table from the decrypted rich4.exe (v3.11).

Outputs two CSVs in the current directory:
  rich4_script_strings.csv  - the #NNNN script records (1354 unique ids)
  rich4_ui_strings.csv      - non-script Big5 and ASCII strings found in the data section

Usage: extract_strings.py <path-to-plain-rich4.exe>
"""
import csv
import re
import sys

DGROUP_FILE = 0x61600   # raw file offset of the DGROUP section data
DGROUP_VA = 0x463000    # virtual address of the same
DGROUP_SIZE = 0x26C00
POOL_START = 0x6283C    # first script record (#0000)
POOL_END = 0x6AA10      # last script record end


def decode(raw):
    """Decode Big5; returns (text, ok)."""
    try:
        return raw.decode('big5'), True
    except Exception:
        return raw.decode('big5', 'replace'), False


def extract_script(plain):
    pool = plain[POOL_START:POOL_END]
    first_by_id = {}
    i = 0
    while i < len(pool):
        if pool[i:i + 5].startswith(b'#') and pool[i + 1:i + 5].isdigit():
            nid = int(pool[i + 1:i + 5])
            j = pool.find(b'\x00', i)
            if j < 0:
                break
            if nid not in first_by_id:      # keep first (canonical) copy
                first_by_id[nid] = (POOL_START + i, pool[i + 5:j])
            i = j + 1
        else:
            i += 1
    return first_by_id


def extract_other(plain):
    sec = plain[DGROUP_FILE:DGROUP_FILE + DGROUP_SIZE]

    def valid_byte(c):
        return c == 0x0A or 0x20 <= c <= 0x7E or 0xA1 <= c <= 0xF9 or 0x80 <= c <= 0xA0

    out = []
    i = 0
    n = len(sec)
    while i < n:
        j = i
        while j < n and sec[j] != 0 and valid_byte(sec[j]):
            j += 1
        if j - i >= 4 and j < n and sec[j] == 0:
            raw = sec[i:j]
            if not (raw.startswith(b'#') and len(raw) >= 5 and raw[1:5].isdigit()):
                has_big5 = bool(re.search(rb'[\xa1-\xf9][\x40-\x7e]', raw))
                text, ok = decode(raw)
                out.append((DGROUP_FILE + i, text, ok, has_big5))
            i = j + 1
        else:
            i = j + 1 if j < n else n
    return out


def main(path):
    plain = open(path, 'rb').read()

    with open('rich4_script_strings.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['id', 'file_off', 'va', 'chinese', 'english', 'notes'])
        for nid, (off, raw) in sorted(extract_script(plain).items()):
            text, ok = decode(raw)
            va = DGROUP_VA + (off - DGROUP_FILE)
            w.writerow([nid, hex(off), hex(va), text.replace('\n', '\\n'), '',
                        'OK' if ok else 'DECODE_WARN'])

    with open('rich4_ui_strings.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['file_off', 'va', 'kind', 'text', 'english', 'notes'])
        for off, text, ok, is_big5 in extract_other(plain):
            va = DGROUP_VA + (off - DGROUP_FILE)
            w.writerow([hex(off), hex(va), 'big5' if is_big5 else 'ascii',
                        text.replace('\n', '\\n'), '', 'OK' if ok else 'DECODE_WARN'])

    print("wrote rich4_script_strings.csv and rich4_ui_strings.csv")


if __name__ == '__main__':
    main(sys.argv[1])
