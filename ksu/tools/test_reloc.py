#!/usr/bin/env python3
"""Self-test for ko_absinfix.py: rewrite three UNDEF symbols of a real .ko
against a fake kallsyms and assert that exactly those symbol entries changed,
with st_shndx == SHN_ABS and st_value == the fake address.

  test_reloc.py [ko]

Defaults to ../artifacts/kernelsu-zf8-rc3-officialkey.ko. Exits 0 on pass.
"""
import os
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ABSINFIX = os.path.join(HERE, "ko_absinfix.py")
DEFAULT_KO = os.path.join(HERE, os.pardir, "artifacts", "kernelsu-zf8-rc3-officialkey.ko")

SHN_ABS = 0xFFF1
FAKE_BASE = 0xFFFFFFC010000000


def symtab(blob):
    """[(offset, name, st_shndx, st_value)] for every symbol but the null one."""
    e_shoff, = struct.unpack_from("<Q", blob, 0x28)
    e_shentsize, = struct.unpack_from("<H", blob, 0x3A)
    e_shnum, = struct.unpack_from("<H", blob, 0x3C)
    e_shstrndx, = struct.unpack_from("<H", blob, 0x3E)
    str_off, = struct.unpack_from("<Q", blob, e_shoff + e_shstrndx * e_shentsize + 0x18)
    tab = None
    for i in range(e_shnum):
        base = e_shoff + i * e_shentsize
        typ, = struct.unpack_from("<I", blob, base + 4)
        if typ == 2:  # SHT_SYMTAB
            tab = base
    if tab is None:
        raise SystemExit("no .symtab")
    off, = struct.unpack_from("<Q", blob, tab + 0x18)
    size, = struct.unpack_from("<Q", blob, tab + 0x20)
    link, = struct.unpack_from("<I", blob, tab + 0x28)
    name_base, = struct.unpack_from("<Q", blob, e_shoff + link * e_shentsize + 0x18)
    out = []
    for s in range(1, size // 24):
        o = off + s * 24
        st_name, _, _, shndx = struct.unpack_from("<IBBH", blob, o)
        value, = struct.unpack_from("<Q", blob, o + 8)
        end = blob.index(b"\0", name_base + st_name)
        out.append((o, blob[name_base + st_name:end].decode(), shndx, value))
    return out


def main():
    ko = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_KO
    src = open(ko, "rb").read()
    undef = [s for s in symtab(src) if s[2] == 0]
    if len(undef) < 3:
        raise SystemExit("%s has only %d UNDEF symbols" % (ko, len(undef)))
    picked = undef[:3]
    want = {name: FAKE_BASE + 0x1000 * (i + 1) for i, (_, name, _, _) in enumerate(picked)}

    with tempfile.TemporaryDirectory() as tmp:
        ks = os.path.join(tmp, "fake_kallsyms.txt")
        out = os.path.join(tmp, "out.ko")
        with open(ks, "w") as f:
            f.write("ffffffc010000000 T _text\n")
            for name, addr in want.items():
                f.write("%016x T %s\n" % (addr, name))
        r = subprocess.run([sys.executable, ABSINFIX, ko, ks, out],
                           capture_output=True, text=True)
        if r.returncode != 0:
            raise SystemExit("ko_absinfix failed: " + r.stderr.strip())
        print("  ko_absinfix: " + r.stdout.strip().splitlines()[0])
        new = open(out, "rb").read()

    if len(new) != len(src):
        raise SystemExit("size changed: %d -> %d" % (len(src), len(new)))
    edited = {o for o in range(len(src)) if src[o] != new[o]}

    fails = []
    expected = set()
    before = {name: (o, shndx, value) for o, name, shndx, value in symtab(src)}
    after = {name: (o, shndx, value) for o, name, shndx, value in symtab(new)}
    for name, addr in want.items():
        o, shndx, value = after[name]
        expected.update(range(o + 6, o + 8))    # st_shndx
        expected.update(range(o + 8, o + 16))   # st_value
        if shndx != SHN_ABS:
            fails.append("%s: st_shndx=%#x, want %#x" % (name, shndx, SHN_ABS))
        if value != addr:
            fails.append("%s: st_value=%#x, want %#x" % (name, value, addr))
        print("  ✓  %-32s st_shndx=0x%04x st_value=%#x" % (name, shndx, value))
    if edited - expected:
        fails.append("touched bytes outside the three symbols: %s"
                     % " ".join(hex(o) for o in sorted(edited - expected)[:8]))
    for name, before_entry in before.items():
        if name not in want and after[name] != before_entry:
            fails.append("%s changed but should not have" % name)
            break

    if fails:
        print("\nFAIL")
        for f in fails:
            print("  " + f)
        return 1
    print("\nPASS: 3 symbols became SHN_ABS with fake addresses; nothing else moved")
    return 0


if __name__ == "__main__":
    sys.exit(main())
