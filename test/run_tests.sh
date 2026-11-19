#!/bin/sh
# PC tests for the AirPlay mirroring receiver: crypto backend, frame splitter, AAC decoder.
# Needs ZIG (zig cc) and python.
# Usage: ZIG=/path/to/zig sh airplay-mirror/test/run_tests.sh
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
AP=$(cd "$HERE/.." && pwd)
command -v cygpath >/dev/null 2>&1 && AP=$(cygpath -m "$AP")
: "${ZIG:?set ZIG to the zig executable}"
OUT=${OUT:-$AP/build/pc}
mkdir -p "$OUT"
TP=$AP/third_party
CC="$ZIG cc -target x86_64-windows-gnu -O1 -w"
INC="-I$AP/port -I$AP/port/ossl -I$TP/uxplay/lib -I$TP/mbedtls/include -I$TP/monocypher -DMBEDTLS_CONFIG_FILE=\"ap_mbedtls_config.h\""
MBED=""
for f in aes gcm cipher cipher_wrap block_cipher md5 sha1 sha256 sha512 bignum bignum_core constant_time platform_util platform; do
    MBED="$MBED $TP/mbedtls/library/$f.c"
done
COMMON="$AP/port/crypto_port.c $AP/port/ossl/ossl_compat.c $TP/monocypher/monocypher.c $TP/monocypher/monocypher-ed25519.c $TP/uxplay/lib/utils.c $MBED"

$CC $INC -o "$OUT/test_crypto.exe" "$AP/test/test_crypto.c" $COMMON
$CC $INC -o "$OUT/bn_calc.exe" "$AP/test/bn_calc.c" $COMMON

$CC -I$AP/src -o "$OUT/test_split.exe" "$AP/test/test_split.c" "$AP/src/ap_video_link.c" -DAP_SPLIT_ONLY

# AAC decoder (src/ap_adec.c + FFmpeg subset) against ISO conformance references (test/data)
FFS=""
for f in $(grep -v '^#' "$AP/port/ffmpeg/SOURCES"); do FFS="$FFS $TP/ffmpeg/$f"; done
$ZIG cc -target x86_64-windows-gnu -O2 -std=c17 -w -DHAVE_AV_CONFIG_H -I$AP/port/ffmpeg -I$TP/ffmpeg -I$AP/src     -o "$OUT/test_adec.exe" "$AP/test/test_adec.c" "$AP/src/ap_adec.c" "$AP/port/ffmpeg/ap_ff_shim.c" $FFS

rc=0
python -I "$AP/test/test_adec.py" check "$OUT/test_adec.exe" "$AP/test/data" "$OUT/adec" || rc=1
"$OUT/test_split.exe" || rc=1
"$OUT/test_crypto.exe" "$OUT" || rc=1
python -I "$AP/test/test_bn.py" "$OUT/bn_calc.exe" || rc=1
exit $rc
