#!/usr/bin/env python3
"""Apply zh->en translations from translations/*.tsv + glossary.py to the string CSVs."""
import csv, glob, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'translations'))
from glossary import GLOSSARY


def _norm(s):
    # normalize for lookup only: fullwidth ascii -> ascii, tilde variants -> '~'
    out = []
    for ch in s:
        o = ord(ch)
        if ch in ('\uff01','!'):  # both become '!'
            out.append('!')
        elif o == 0xFF1F or ch == '?':
            out.append('?')
        elif o == 0xFF1A or ch == ':':
            out.append(':')
        elif o == 0xFF0C or ch == ',':
            out.append(',')
        elif ch in ('\u223c','\uff5e','~'):
            out.append('~')
        elif 0xFF01 <= o <= 0xFF5E:
            out.append(chr(o - 0xFEE0))
        else:
            out.append(ch)
    return ''.join(out)

trans = {}
for path in sorted(glob.glob(os.path.join(os.path.dirname(__file__), '..', 'translations', 'batch*.tsv'))):
    for line in open(path, encoding='utf-8'):
        line = line.rstrip('\n')
        if not line or line.startswith('#'):
            continue
        if '\t' not in line:
            print(f"WARN: no tab in {path}: {line[:40]}")
            continue
        zh, en = line.split('\t', 1)
        trans[_norm(zh)] = en

print(f"loaded {len(trans)} translations")

def apply_csv(path, text_key):
    rows = list(csv.DictReader(open(path, newline='', encoding='utf-8')))
    fields = [f.strip('\ufeff') for f in rows[0].keys()]
    n_ok = n_miss = 0
    missing = set()
    for row in rows:
        reader = csv.DictReader(open(path, newline='', encoding='utf-8'))
        break
    # re-read with proper fieldnames (BOM safety)
    with open(path, newline='', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        fields = reader.fieldnames
        rows = list(reader)
    key = 'chinese' if 'chinese' in fields else 'text'
    for row in rows:
        zh = row[key]
        zn = _norm(zh)
        en = ''
        if zn in trans:
            en = trans[zn]
        elif zn in GLOSSARY:
            en = GLOSSARY.get(zh) or GLOSSARY[zn]
        elif all(ord(c) < 128 for c in zh):
            en = zh  # ascii & number formats pass through
            n_ok += 1
            row['english'] = en
            continue
        else:
            n_miss += 1
            missing.add(zh)
            row['english'] = ''
        if en:
            n_ok += 1
        row['english'] = en
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    print(f"{path}: translated {n_ok}, missing {n_miss}")
    return missing

m1 = apply_csv('strings/rich4_script_strings.csv', 'chinese')
m2 = apply_csv('strings/rich4_ui_strings.csv', 'text')
allmissing = m1 | m2
with open('/tmp/missing_translations.txt', 'w') as f:
    for t in sorted(allmissing):
        f.write(t + '\n')
print(f"total missing: {len(allmissing)} (written to /tmp/missing_translations.txt)")
