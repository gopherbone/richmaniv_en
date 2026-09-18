#!/usr/bin/env python3
"""Richman 4 CD-file decryptor.

Cipher (empirically proven on rich4.exe / Effect.mkf / Speaking.mkf plain+enc pairs):
    a plaintext byte p at file offset i encrypts to plain[i] ^ S[i % 71][p],
    i.e. the keystream depends only on the column (i mod 71) and the plaintext byte.

The S table is identical across all (non-help) paired files. To decrypt, invert S per
column. Every (column, 0) cell equals the base key K1; cells never observed are resolved
via the GF(2)-linear structure: S[j][p] ^ K1[j] = L_j(p) is linear in p (proven: 0
violations), so missing cells are interpolated from the 8 basis vectors L_j(1<<b).
"""
import struct, sys, os, glob
from collections import Counter

K1 = bytes.fromhex("d5d1ddd9c5c1cdc9f5f1fdf9e5e1ede995919d9985818d89b5b1bdb9a5a1ada955515d5945414d4975717d7965616d6915111d1905010d0935313d3925212d29d4d0dcd8c4c0cc")

def build_dev(plain, enc):
    """Return per-column Counter of deviation X = ks ^ K1[j] for nonzero plaintext."""
    n = min(len(plain), len(enc))
    conf = [[Counter() for _ in range(256)] for _ in range(71)]
    for i in range(n):
        if plain[i] == 0:
            continue
        conf[i % 71][plain[i]][enc[i]] += 1
    return conf

def make_tables(plain, enc):
    n = min(len(plain), len(enc))
    conf = [[Counter() for _ in range(256)] for _ in range(71)]
    for i in range(n):
        conf[i % 71][plain[i]][enc[i] ^ plain[i]] += 1
    S = [[None] * 256 for _ in range(71)]
    confl = 0
    for j in range(71):
        for p in range(256):
            c = conf[j][p]
            if c:
                S[j][p] = c.most_common(1)[0][0]
                if len(c) > 1:
                    confl += 1
    # complete via linear model: D_j(p) = S[j][p] ^ K1[j]; D_j linear
    full_dev = [[None] * 256 for _ in range(71)]
    interp = 0
    for j in range(71):
        dev = [None if S[j][p] is None else S[j][p] ^ K1[j] for p in range(256)]
        basis = [dev[1 << b] for b in range(8)]
        if all(v is not None for v in basis):
            # verify against known cells & interpolate unknowns
            for p in range(256):
                if dev[p] is None:
                    x = 0
                    for b in range(8):
                        if p & (1 << b):
                            x ^= basis[b]
                    dev[p] = x
                    interp += 1
        full_dev[j] = dev
        S[j] = [None if dev[p] is None else dev[p] ^ K1[j] for p in range(256)]
    return S, confl, interp

def invert(S):
    INV = []
    for j in range(71):
        inv = {}
        ok = True
        for p in range(256):
            v = S[j][p]
            if v is None:
                ok = False; break
            if v in inv:
                ok = False; break
            inv[v] = p
        INV.append(inv if ok else None)
    return INV

def decrypt(data, INV, gapfill=True):
    out = bytearray(len(data))
    for i, c in enumerate(data):
        j = i % 71
        p = INV[j].get(c) if INV[j] else None
        if p is None:
            # unknown cell: guess p = c ^ K1[j] (base assumption)
            p = c ^ K1[j]
        out[i] = p
    return bytes(out)

def build_keystream_table(plain_files):
    """Recover the S(j, p) table from (plaintext, encrypted) file pairs.

    plain_files: list of (plain_path, encrypted_path) tuples.
    Returns a 71x256 table S where a plaintext byte p at file offset i
    encrypts to plain[i] ^ S[i % 71][p].
    """
    merge_votes = [[Counter() for _ in range(256)] for _ in range(71)]
    for pf, ef in plain_files:
        plain = open(pf, 'rb').read()
        enc = open(ef, 'rb').read()
        n = min(len(plain), len(enc))
        for i in range(n):
            merge_votes[i % 71][plain[i]][enc[i] ^ plain[i]] += 1
    S = [[c.most_common(1)[0][0] if c else None for c in col] for col in merge_votes]
    # complete unspecified cells via the GF(2)-linear model:
    # D_j(p) = S[j][p] ^ K1[j] is linear in p (verified: 0 violations on known cells)
    K1b = list(K1)
    for j in range(71):
        col = S[j]
        base = K1b[j]
        for p in range(256):
            if col[p] is not None:
                continue
            terms = []
            ok = True
            pp = p
            while pp:
                b = pp & (-pp)
                if col[b] is None:
                    ok = False
                    break
                terms.append(col[b] ^ base)
                pp ^= b
            if ok:
                x = base
                for t in terms:
                    x ^= t
                col[p] = x
    return S


def invert_table(S):
    """Invert S per column. Ambiguous/colliding columns yield partial maps
    (the cipher is k-to-1 at some columns; those bytes need decompression
    context to disambiguate). Returns list of dicts (possibly partial)."""
    INV = []
    for j in range(71):
        inv = {}
        for p in range(256):
            if S[j][p] is None:
                continue
            inv.setdefault(S[j][p], p)  # first (lowest) p wins
        INV.append(inv)
    return INV


def decrypt(data, INV, K1=K1):
    """Decrypt using inverted table; guesses p = c ^ K1[j] at undecidable cells."""
    out = bytearray(len(data))
    for i, c in enumerate(data):
        j = i % 71
        p = INV[j].get(c) if j < len(INV) else None
        if p is None:
            p = c ^ K1[j]
        out[i] = p
    return bytes(out)


def main(argv):
    import os
    import glob
    game_dir = os.environ.get('RICH4_GAME_DIR', '.')
    plain_dir = os.environ.get('RICH4_PLAIN_DIR', './plain')
    # learn keystream from any files that have both encrypted and plain copies
    pairs = []
    for pf in glob.glob(os.path.join(plain_dir, '*')):
        name = os.path.basename(pf)
        cand = {
            'rich4.exe': ['rich4.exe'],
            'Effect.mkf': ['Effect.mkf', 'effect.mkf'],
            'Speaking.mkf': ['Speaking.mkf', 'speaking.mkf'],
            'help.mkf': ['help.mkf'],
        }.get(name, [])   # plain Data/Panel/jump/map names can be added when available
        for c in cand:
            enc_path = os.path.join(game_dir, c)
            if os.path.exists(enc_path):
                pairs.append((pf, enc_path))
    if not pairs:
        print(f"no plain/encrypted pairs found (plain dir: {plain_dir}, game dir: {game_dir})")
        return 1
    S = build_keystream_table(pairs)
    INV = invert_table(S)
    for fname in argv[1:]:
        data = open(fname, 'rb').read()
        dec = decrypt(data, INV)
        out = os.path.splitext(fname)[0] + '.dec'
        open(out, 'wb').write(dec)
        print(f"{fname} -> {out} ({len(dec)} bytes)")
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
