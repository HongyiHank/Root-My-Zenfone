#!/bin/bash
# Rebuild kernelsu-zf8-rc3-officialkey.ko from this directory plus a kernel tree.
#
#   ./build.sh <workdir> <kernel-source-tree> [out.ko]
#
# The kernel tree is the ASUS 33.0210.0210.296 source drop, which is 5.4.147 --
# not the 5.4.210-qgki-perf the device runs, because ASUS published no drop for
# that build. This script copies it, applies patch/0003, configures it with
# config/zf8-module.config and builds the module from upstream v4.2.0-rc3 with
# patch/0001 and patch/0002. Expect 15-25 minutes and about 5 GB.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
W=${1:?usage: build.sh <workdir> <kernel-source-tree> [out.ko]}
SRC=${2:?usage: build.sh <workdir> <kernel-source-tree> [out.ko]}
OUT=${3:-$W/kernelsu-zf8-rc3-officialkey.ko}

TAG=v4.2.0-rc3
COMMIT=239e1e8871b8fcd51a6e5b3002e0ba522fdd99fb
UPSTREAM=https://github.com/ReSukiSU/ReSukiSU.git
CC=aarch64-linux-gnu-gcc-12
export ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-

KERNEL=$W/kernel
TREE=$W/ReSukiSU
mkdir -p "$W"

# 1. kernel tree -------------------------------------------------------------
# 0003 makes cfi_check and jump_entries/num_jump_entries unconditional and
# teaches modpost to emit .cfi_check. Without it struct module is 8 bytes short
# and the loader misplaces every relocation.
[ -d "$KERNEL" ] || cp -a "$SRC" "$KERNEL"
cd "$KERNEL"
# The manifest is the only base check that bites: git apply ignores the index
# lines in the patch, so it will happily apply to a tree with different content
# as long as the context matches. Run this on both paths, and skip the whole
# step when the patch is already in the tree so the script can be re-run.
PATCH="$HERE/patch/0003-zf8-kernel-side.patch"
if patch -p1 -R --dry-run --forward < "$PATCH" >/dev/null 2>&1; then
    echo "0003 already applied"
else
    ( cd "$KERNEL" && sha256sum -c "$HERE/patch/0003.files.sha256" >/dev/null ) || {
        echo "kernel tree does not match patch/0003.files.sha256"; exit 1; }
    # git apply too, so a fuzzed hunk cannot land; GNU patch only for plain dirs.
    if git -C "$KERNEL" rev-parse --git-dir >/dev/null 2>&1; then
        git -C "$KERNEL" apply --check "$PATCH"
        git -C "$KERNEL" apply "$PATCH"
    else
        patch -p1 --forward < "$PATCH"
    fi
fi
cp "$HERE/config/zf8-module.config" .config
# DISABLE_WRAPPER keeps CC from being replaced by scripts/gcc-wrapper.py, which
# mangles compiler errors and fails modules_prepare.
make DISABLE_WRAPPER=1 CC=$CC olddefconfig  >"$W/olddefconfig.log" 2>&1
make DISABLE_WRAPPER=1 CC=$CC syncconfig   >>"$W/olddefconfig.log" 2>&1
make DISABLE_WRAPPER=1 CC=$CC modules_prepare -j"$(nproc)" >"$W/prepare.log" 2>&1
# modules_prepare does not generate the SELinux class headers; the module
# includes objsec.h, which pulls them in. genheaders is the kernel's own tool.
if [ ! -f security/selinux/flask.h ]; then
    gcc -I include/uapi -I include -I security/selinux/include \
        scripts/selinux/genheaders/genheaders.c -o "$W/genheaders"
    "$W/genheaders" security/selinux/flask.h security/selinux/av_permissions.h
fi

# syncconfig rewrites the version string, so override it afterwards.
echo "5.4.210-qgki-perf-g6e91db764350" > include/config/kernel.release
printf '#define UTS_RELEASE "5.4.210-qgki-perf-g6e91db764350"\n' > include/generated/utsrelease.h
# modpost is handed $(wildcard vmlinux) and would harvest the tree's __crc_*
# symbols into __versions; an empty Module.symvers and no vmlinux keep it at 0.
if [ -f vmlinux ]; then mv vmlinux "$W/vmlinux.keep"; fi
: > Module.symvers

# 2. module source -----------------------------------------------------------
if [ ! -d "$TREE/.git" ]; then
    git clone --quiet "$UPSTREAM" "$TREE"
fi
git -C "$TREE" checkout --quiet "$TAG"
[ "$(git -C "$TREE" rev-parse HEAD)" = "$COMMIT" ] || { echo "tag $TAG is not $COMMIT"; exit 1; }
git -C "$TREE" apply "$HERE/patch/0001-zf8-device.patch"
git -C "$TREE" apply "$HERE/patch/0002-zf8-tag-build.patch"

# 3. build -------------------------------------------------------------------
find "$TREE/kernel" -name '*.o' -delete
rm -f "$TREE"/kernel/kernelsu.ko "$TREE"/kernel/kernelsu.mod*
# KSU_EXPECTED_* is the seventh apk_sign_keys[] entry: this release APK's DER
# length and SHA-256. Without it apk_sign.c checks six keys and .text differs.
make CC=$CC KBUILD_MODPOST_WARN=1 M="$TREE/kernel" \
     CONFIG_KSU=m CONFIG_KSU_TRACEPOINT_HOOK=y CONFIG_KSU_MULTI_MANAGER_SUPPORT=y \
     DISABLE_WRAPPER=1 \
     KSU_EXPECTED_SIZE=887 \
     KSU_EXPECTED_HASH=d3469712b6214462764a1d8d3e5cbe1d6819a0b629791b9f4101867821f1df64 \
     modules -j"$(nproc)" >"$W/build.log" 2>&1
aarch64-linux-gnu-strip --strip-debug -o "$OUT" "$TREE/kernel/kernelsu.ko"

# 4. gates -------------------------------------------------------------------
echo "--- built $OUT"
# --pre-reloc lets the UNDEF check be informational; every ABI check stays fatal.
python3 "$HERE/tools/ko_loadable.py" verify "$OUT" --pre-reloc || {
    echo "ABI gates failed; the kernel tree probably lacks patch/0003"; exit 1; }
UNDEF=$(aarch64-linux-gnu-nm "$OUT" | awk '$1=="U"' | wc -l)
echo "--- UNDEF: $UNDEF"
[ "$UNDEF" = 193 ] || { echo "expected 193 UNDEF, got $UNDEF"; exit 1; }
echo "--- the artifact carries 193 UNDEF and 336,336 bytes; this build will differ"
echo "    in .symtab and the .rodata.str1.8 tail by a few bytes (binutils version),"
echo "    every SHF_ALLOC section is otherwise byte-identical."
