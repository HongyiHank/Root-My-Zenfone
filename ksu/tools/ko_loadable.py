#!/usr/bin/env python3
"""Turn a ReSukiSU/kernelsu.ko built off-tree into a module the ZF8 kernel will
insmod, and check the result.

  ko_loadable.py build <in.ko> <link_kallsyms> <delta_hex> <out.ko>
  ko_loadable.py verify <ko> [--pre-reloc]

The module is built with KBUILD_MODPOST_WARN=1 and an empty Module.symvers, so
modpost turns "symbol not exported" into a warning and the link emits roughly
200 unresolved symbols. The device then rejects it in one of two ways, in this
order: "no symbol version for module_layout" while the CRC table is consulted,
then "overflow in relocation type 275" once a RELATIVE relocation is computed
from a leftover UNDEF value. Both come from the link, not from the source, and
both have to be gone before the module loads.

The ABI gates come from the kernel-side build tree, not from this tool: the
input must already be built against a tree whose struct module is 960 bytes.
What is checked here, all four of which must hold:

  (1) .gnu.linkonce.this_module sh_size == 0x3c0 (960) and the relocation
      offsets that a cacheline-aligned struct hides (__cfi_check 0x108,
      init_module 0x188, cleanup_module 0x378)
  (2) __versions sh_size == 0, so no version lookup can fail
  (3) vermagic tail is exactly "SMP preempt mod_unload modversions aarch64"
  (4) no UNDEF symbol is left; ko_absinfix.py rewrote each one to SHN_ABS

--pre-reloc makes only check (4) informational, so a build can gate on (1)-(3)
without accepting a broken layout. Without it all four must pass.

Verifying (1)-(3) alone passes on the shipped artifact, which still has 193
UNDEF; that is why (4) exists and why an insmod after only those three fails
with an unresolved symbol.

link_kallsyms is the build tree's own symbol table, taken at build time:
`aarch64-linux-gnu-nm vmlinux` or the kernel's System.map, one "addr type
name" line per symbol. Those addresses are pre-KASLR, so they are the same on
every boot and never come from the device.

delta is the KASLR slide of one boot: the PoC log prints "runtime _text=0x..."
and link_kallsyms prints the link-time _text on its first line, so
delta = runtime _text - link-time _text. The PoC log only carries point
readings of that boot (runtime _text, POOL_OPS runtime=), never a full runtime
kallsyms; a full dump would have to come from the boot's /proc/kallsyms, which
kptr_restrict may zero out. build therefore adds delta to the link-time table
instead, and prints the resulting first line so it can be compared with the
log's runtime _text before the module is written. delta is per-boot: after a
reboot the addresses are wrong and the module has to be rebuilt, and a wrong
delta shows up as "Unknown symbol" or as relocation type 275 again.

build writes out.ko and, next to it, out.ko.kallsyms_runtime.txt, the shifted
table handed to ko_absinfix.py; verify reads only out.ko.
"""
import os
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ABSINFIX = os.path.join(HERE, "ko_absinfix.py")

REQUIRE_VERMAGIC_TAIL = "SMP preempt mod_unload modversions aarch64"
REQUIRE_THIS_MODULE_SIZE = 0x3C0


def shdr_sections(blob):
    """[(index, name, header offset, sh_size)] for every section."""
    assert blob[:4] == b"\x7fELF" and blob[4] == 2, "not ELF64"
    e_shoff, = struct.unpack_from("<Q", blob, 0x28)
    e_shentsize, = struct.unpack_from("<H", blob, 0x3A)
    e_shnum, = struct.unpack_from("<H", blob, 0x3C)
    e_shstrndx, = struct.unpack_from("<H", blob, 0x3E)
    str_off, = struct.unpack_from("<Q", blob, e_shoff + e_shstrndx * e_shentsize + 0x18)
    out = []
    for i in range(e_shnum):
        base = e_shoff + i * e_shentsize
        nm, = struct.unpack_from("<I", blob, base)
        sz, = struct.unpack_from("<Q", blob, base + 0x20)
        end = blob.index(b"\0", str_off + nm)
        out.append((i, blob[str_off + nm:end].decode(), base, sz))
    return out


def shdr_fields(blob, want):
    """Every field of the named section, or None."""
    e_shoff, = struct.unpack_from("<Q", blob, 0x28)
    e_shentsize, = struct.unpack_from("<H", blob, 0x3A)
    e_shnum, = struct.unpack_from("<H", blob, 0x3C)
    e_shstrndx, = struct.unpack_from("<H", blob, 0x3E)
    str_off, = struct.unpack_from("<Q", blob, e_shoff + e_shstrndx * e_shentsize + 0x18)
    for i in range(e_shnum):
        base = e_shoff + i * e_shentsize
        nm, = struct.unpack_from("<I", blob, base)
        end = blob.index(b"\0", str_off + nm)
        if blob[str_off + nm:end].decode() != want:
            continue
        _, typ, _, _, off, size, link, _, _, entsize = struct.unpack_from("<IIQQQQIIQQ", blob, base)
        return {"type": typ, "off": off, "size": size, "link": link, "entsize": entsize}
    return None


def this_module_relocs(blob):
    """[(r_offset, symbol name)] from .rela.gnu.linkonce.this_module.

    A correct layout puts __cfi_check at 0x108 and init_module at 0x188.
    sh_size cannot tell: struct module is cacheline-aligned, so a build without
    the CFI field still rounds up to 0x3c0 and only the offsets move.
    """
    rela = shdr_fields(blob, ".rela.gnu.linkonce.this_module")
    if not rela or not rela["entsize"]:
        return []
    symtab = None
    for _, nm, base, _ in shdr_sections(blob):
        if nm == ".symtab":
            _, _, _, _, off, size, link, _, _, entsize = struct.unpack_from("<IIQQQQIIQQ", blob, base)
            symtab = {"off": off, "link": link, "entsize": entsize}
    if not symtab:
        return []
    strtab = shdr_fields(blob, ".strtab")
    out = []
    for o in range(rela["off"], rela["off"] + rela["size"], rela["entsize"]):
        r_off, r_info = struct.unpack_from("<QQ", blob, o)
        si = r_info >> 32
        if not si:
            continue
        name_off, = struct.unpack_from("<I", blob, symtab["off"] + si * symtab["entsize"])
        end = blob.index(b"\0", strtab["off"] + name_off)
        out.append((r_off, blob[strtab["off"] + name_off:end].decode()))
    return out


def apply_delta(link_kallsyms, delta, runtime_kallsyms):
    """Write the link-time table shifted by delta; returns the line count."""
    n = 0
    with open(runtime_kallsyms, "w") as out:
        for line in open(link_kallsyms):
            p = line.split()
            if len(p) < 3:
                continue
            try:
                a = int(p[0], 16)
            except ValueError:
                continue
            out.write("%016x %s %s\n" % (a + delta, p[1], p[2]))
            n += 1
    return n


def zero_section_size(blob, want):
    """Declare a section empty; only the header changes, the bytes stay."""
    hits = [(i, base, sz) for i, nm, base, sz in shdr_sections(blob) if nm == want]
    for _, base, _ in hits:
        struct.pack_into("<Q", blob, base + 0x20, 0)
    return hits


def verify(ko, pre_reloc=False):
    blob = open(ko, "rb").read()
    secs = {nm: (i, base, sz) for i, nm, base, sz in shdr_sections(blob)}
    vm = subprocess.run(["strings", ko], capture_output=True, text=True).stdout
    tail_ok = any(REQUIRE_VERMAGIC_TAIL in ln for ln in vm.splitlines())
    nm = subprocess.run(["aarch64-linux-gnu-nm", ko], capture_output=True, text=True)
    if nm.returncode == 0:
        undef = nm.stdout.count(" U ")
        undef_got = "%d" % undef
    else:
        undef = -1
        undef_got = "aarch64-linux-gnu-nm unavailable"
    rel = dict(this_module_relocs(blob))
    layout_ok = rel.get(0x108) == "__cfi_check" and rel.get(0x188) == "init_module" and rel.get(0x378) == "cleanup_module"
    layout_got = "cfi=%s init=%s exit=%s" % (
        hex(0x108) if rel.get(0x108) == "__cfi_check" else rel.get(0x108, "-"),
        hex(0x188) if rel.get(0x188) == "init_module" else rel.get(0x188, "-"),
        hex(0x378) if rel.get(0x378) == "cleanup_module" else rel.get(0x378, "-"))
    rows = [
        ("this_module sh_size == 0x3c0",
         secs.get(".gnu.linkonce.this_module", (0, 0, -1))[2] == REQUIRE_THIS_MODULE_SIZE,
         hex(secs.get(".gnu.linkonce.this_module", (0, 0, -1))[2])),
        ("__versions sh_size == 0",
         secs.get("__versions", (0, 0, -1))[2] == 0,
         hex(secs.get("__versions", (0, 0, -1))[2])),
        ("vermagic tail exact", tail_ok, "ok" if tail_ok else "mismatch"),
        ("layout offsets 0x108/0x188/0x378", layout_ok, layout_got),
        ("no UNDEF left", undef == 0, undef_got),
    ]
    for label, ok, got in rows:
        print("  %s  %-32s  got=%s" % ("✓" if ok else "✗", label, got))
    # A module that has not been relocated yet is expected to fail the UNDEF row
    # and nothing else; --pre-reloc makes only that row informational so a build
    # can gate on the ABI checks without accepting a broken layout.
    if pre_reloc:
        return all(ok for label, ok, _ in rows if label != "no UNDEF left")
    return all(ok for _, ok, _ in rows)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    cmd = sys.argv[1]

    if cmd == "verify":
        if len(sys.argv) not in (3, 4):
            print(__doc__)
            return 2
        return 0 if verify(sys.argv[2], "--pre-reloc" in sys.argv[3:]) else 1

    if cmd == "build":
        if len(sys.argv) != 6:
            print(__doc__)
            return 2
        _, _, inko, link_kallsyms, delta_hex, outko = sys.argv
        delta = int(delta_hex, 16)
        rt = outko + ".kallsyms_runtime.txt"

        n = apply_delta(link_kallsyms, delta, rt)
        print("  runtime kallsyms: %d lines (delta=%#x)" % (n, delta))
        with open(rt) as f:
            first = f.readline().split()
        print("  first line after delta: _text -> %s (must equal the log's runtime _text)" % first[0])

        print("  (4) relocating UNDEF (ko_absinfix.py)")
        tmp1 = outko + ".abs"
        r = subprocess.run([sys.executable, ABSINFIX, inko, rt, tmp1],
                           capture_output=True, text=True)
        print("    " + (r.stdout.strip().splitlines() or ["(no output)"])[0])
        if r.returncode != 0:
            print("    ko_absinfix failed: " + r.stderr.strip()[:200], file=sys.stderr)
            return 1

        print("  (2) zeroing __versions sh_size")
        blob = bytearray(open(tmp1, "rb").read())
        hits = zero_section_size(blob, "__versions")
        for i, _, sz in hits:
            print("    section #%d __versions: %s -> 0x0" % (i, hex(sz)))
        if not hits:
            print("    __versions section not found", file=sys.stderr)
            return 1
        open(outko, "wb").write(blob)
        os.unlink(tmp1)

        print("  checking the result")
        ok = verify(outko)
        print("  => %s" % ("all four hold, module can be insmod'ed" if ok else "still failing"))
        return 0 if ok else 1

    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
