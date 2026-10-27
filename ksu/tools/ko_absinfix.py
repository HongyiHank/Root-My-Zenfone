#!/usr/bin/env python3
"""Rewrite the UNDEF symbols of a module .ko into absolute symbols (SHN_ABS)
carrying addresses read from one boot's kallsyms dump.

  ko_absinfix.py in.ko kallsyms.txt out.ko [sym ...]

The module is linked against a kallsyms whose addresses are link-time, so
every symbol it imports is an UNDEF the loader would have to resolve against
the running kernel. The ZF8 build has no symbol versions to resolve against
(see ko_loadable.py), so the addresses are baked into the symbol table instead.
The rewrite only touches st_shndx and st_value; no relocation is resolved and
no section bytes move.

Names given on the command line restrict the rewrite to those symbols.
Without them every UNDEF whose name appears in the kallsyms dump is rewritten,
whether or not the kernel exports it through __ksymtab: an exported symbol is
already resolved by the loader, and reproducing its address is harmless, while
treating the two cases differently would leave a gap in the coverage count that
the caller cannot see. UNDEF names missing from the dump are reported and left
alone; a dump entry with address 0 is reported and left alone too, because a
zero st_value would make the module read through a null pointer.
"""
import struct
import sys

SHN_ABS = 0xFFF1


def load_kallsyms(path):
    """Map symbol name -> address from kallsyms text; first column is hex."""
    addrs = {}
    for line in open(path):
        parts = line.split()
        if len(parts) < 3:
            continue
        try:
            addrs[parts[2]] = int(parts[0], 16)
        except ValueError:
            continue
    return addrs


def main():
    if len(sys.argv) < 4:
        sys.exit(__doc__.strip() + "\n\nusage: ko_absinfix.py in.ko kallsyms.txt out.ko [sym ...]")
    inp, ks_path, outp = sys.argv[1], sys.argv[2], sys.argv[3]
    want = set(sys.argv[4:]) if len(sys.argv) > 4 else None
    addrs = load_kallsyms(ks_path)

    d = bytearray(open(inp, "rb").read())
    assert d[:4] == b"\x7fELF" and d[4] == 2, "not ELF64"
    e_shoff, = struct.unpack_from("<Q", d, 0x28)
    e_shentsize, = struct.unpack_from("<H", d, 0x3A)
    e_shnum, = struct.unpack_from("<H", d, 0x3C)
    e_shstrndx, = struct.unpack_from("<H", d, 0x3E)

    def hdr(i):
        o = e_shoff + i * e_shentsize
        name, typ = struct.unpack_from("<II", d, o)
        _, _, off, size, link, _ = struct.unpack_from("<QQQQII", d, o + 8)
        return dict(o=o, name=name, typ=typ, off=off, size=size, link=link)

    symtab = strtab = None
    for i in range(e_shnum):
        h = hdr(i)
        if h["typ"] == 2:  # SHT_SYMTAB
            symtab = h
            strtab = hdr(h["link"])
    if not symtab:
        sys.exit("no .symtab in %s" % inp)

    fixed, skipped, missing = [], [], []
    nsyms = symtab["size"] // 24
    for s in range(1, nsyms):  # entry 0 is the null symbol
        o = symtab["off"] + s * 24
        st_name, _, _, st_shndx = struct.unpack_from("<IBBH", d, o)
        if st_shndx != 0:  # already defined
            continue
        name = bytes(d[strtab["off"] + st_name:]).split(b"\0")[0].decode()
        if want is not None and name not in want:
            continue
        if name not in addrs:
            skipped.append(name)
            continue
        a = addrs[name]
        if a == 0:
            missing.append(name + "(addr0)")
            continue
        struct.pack_into("<H", d, o + 6, SHN_ABS)
        struct.pack_into("<Q", d, o + 8, a)
        fixed.append(name)

    open(outp, "wb").write(bytes(d))
    print("fixed=%d skipped(not in kallsyms)=%d addr0=%d" % (len(fixed), len(skipped), len(missing)))
    if skipped:
        print("SKIPPED:", " ".join(skipped[:20]))
    if missing:
        print("ADDR0:", " ".join(missing[:20]))
    if fixed:
        print("FIXED:", " ".join(fixed[:60]))


main()
