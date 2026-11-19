#!/bin/sh
# Build ap_receiver for MIB2 High (QNX 6.5, armle-v7) with zig as the cross compiler.
#
#   export ZIG=/path/to/zig            (0.16.0)
#   export QNX=/path/to/qnx650/target/qnx6   (QNX 6.5 SDP target tree: usr/include, armle-v7/lib)
#   sh build.sh                        -> build/qnx/ap_receiver (stripped) + ap_receiver.unstripped
#
# Inputs: third_party/ (UxPlay lib, libplist, mbedTLS, Monocypher, FFmpeg AAC decoder subset),
# port/ (QNX compatibility, crypto backend, decoder config), src/ (the receiver).
# The result links only against libc.so.3, libsocket.so.3 and libm.so.2.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
: "${ZIG:?set ZIG to the zig executable (0.16.0)}"
: "${QNX:?set QNX to the QNX 6.5 target tree (.../qnx650/target/qnx6)}"
if command -v cygpath >/dev/null 2>&1; then
    HERE=$(cygpath -m "$HERE")
    QNX=$(cygpath -m "$QNX")
fi
[ -d "$QNX/usr/include" ] && [ -f "$QNX/armle-v7/lib/libc.so.3" ] || { echo "QNX=$QNX is not a QNX 6.5 target tree"; exit 1; }
OUT=${OUT:-$HERE/build/qnx}
mkdir -p "$OUT/obj"
TP=$HERE/third_party
U=$TP/uxplay/lib
PL=$TP/libplist
L="$QNX/armle-v7/lib"

FP="-mfpu=vfpv3-d16 -mfloat-abi=softfp"
QDEFS="-D__QNX__ -D__QNXNTO__ -D__ARM__ -D__arm__ -D__LITTLEENDIAN__ -D__ELF__ -D_QNX_SOURCE
       -D__EXT_QNX -D__EXT_UNIX_MISC -D__EXT_POSIX1_200112 -D__EXT_BSD -D__GNUC__=4"
CC="$ZIG cc -target arm-freestanding-eabi -mcpu=cortex_a9 $FP -Os -mstrict-align -fno-stack-protector
    -fno-strict-aliasing -ffunction-sections -fdata-sections -isystem $QNX/usr/include $QDEFS -std=gnu99"
MBEDCFG="-I$HERE/port -I$TP/mbedtls/include -DMBEDTLS_CONFIG_FILE=\"ap_mbedtls_config.h\""
INC="-I$HERE/port -I$HERE/port/ossl -I$U -I$U/playfair -I$U/llhttp -I$U/mdnsd -I$PL/include
     -I$PL/libcnary/include -I$PL/src -I$TP/monocypher $MBEDCFG"
FFINC="-I$HERE/port/ffmpeg -I$TP/ffmpeg -DHAVE_AV_CONFIG_H -std=c17 -O2"

OBJS=""
fail=0
cc1() {   # cc1 <source> <extra flags...>
    s=$1; shift
    o=$OUT/obj/$(echo "$s" | sed "s|^$TP/||; s|^$HERE/||; s|/|_|g; s|\.c$|.o|")
    if MSYS_NO_PATHCONV=1 $CC -w "$@" -c "$s" -o "$o" 2> "$o.err"; then
        rm -f "$o.err"
        OBJS="$OBJS $o"
    else
        fail=$((fail + 1))
        echo "  compile failed: $s"
        grep -m5 error "$o.err" | cut -c1-240
    fi
}

echo "[1/2] compile"
# UxPlay lib: crypto.c is replaced by port/crypto_port.c; mDNS via the built-in responder
# (lib/mdnsd) rather than an Avahi/Bonjour daemon, so dns_sd/ is left out.
for f in "$U"/*.c "$U"/playfair/*.c "$U"/llhttp/*.c "$U"/mdnsd/*.c; do
    case "$f" in */crypto.c) continue ;; esac
    cc1 "$f" $INC -DHAVE_LIBDL=0 -DPLIST_210 -DPLIST_230 -include "$HERE/port/qnx_fix.h"
done
for f in bplist plist xplist jplist jsmn oplist out-default out-limd out-plutil base64 bytearray hashtable ptrarray time64 common; do
    [ -f "$PL/src/$f.c" ] && cc1 "$PL/src/$f.c" $INC -include "$HERE/port/ap_compat.h" -DHAVE_STRNDUP=1 -DPACKAGE_VERSION=\"2.6\" -DHAVE_STDINT_H=1
done
for f in "$PL"/libcnary/node.c "$PL"/libcnary/node_list.c; do cc1 "$f" $INC; done   # cnary.c is only a demo main()
for f in aes gcm cipher cipher_wrap block_cipher md5 sha1 sha256 sha512 bignum bignum_core constant_time platform_util platform; do
    cc1 "$TP/mbedtls/library/$f.c" $MBEDCFG
done
cc1 "$TP/monocypher/monocypher.c" -I"$TP/monocypher"
cc1 "$TP/monocypher/monocypher-ed25519.c" -I"$TP/monocypher"
cc1 "$HERE/port/crypto_port.c" $INC
cc1 "$HERE/port/ossl/ossl_compat.c" $INC
cc1 "$HERE/port/ap_rt.c" -O2
# AAC decoder: FFmpeg subset (third_party/ffmpeg, file list in port/ffmpeg/SOURCES), built -O2
# (it runs for every audio packet) with the hand-made config in port/ffmpeg.
for f in $(grep -v '^#' "$HERE/port/ffmpeg/SOURCES"); do
    cc1 "$TP/ffmpeg/$f" $FFINC
done
cc1 "$HERE/port/ffmpeg/ap_ff_shim.c" $FFINC
cc1 "$HERE/src/ap_main.c" $INC -I"$HERE/src" -D_GNU_SOURCE
cc1 "$HERE/src/ap_video_link.c" -I"$HERE/src"
cc1 "$HERE/src/ap_audio_link.c" -I"$HERE/src"
cc1 "$HERE/src/ap_adec.c" -I"$HERE/src" $FFINC
[ "$fail" = 0 ] || { echo "$fail file(s) failed to compile"; exit 1; }

echo "[2/2] link"
# Linked twice from the same objects: .unstripped (symbols, for crash analysis) and the stripped one.
for v in unstripped stripped; do
    o=$OUT/ap_receiver; s=-Wl,--strip-all
    [ $v = unstripped ] && { o=$OUT/ap_receiver.unstripped; s=; }
    MSYS_NO_PATHCONV=1 $ZIG cc -target arm-linux-gnueabi -mcpu=cortex_a9 $FP \
        -nostdlib -Wl,-z,lazy -Wl,--dynamic-linker=/usr/lib/ldqnx.so.2 -Wl,--gc-sections $s \
        -o "$o" \
        "$L/crt1.o" "$L/crti.o" "$L/crtbegin.o" $OBJS \
        "$L/libsocket.so.3" "$L/libm.so.2" "$L/libc.so.3" \
        "$L/crtend.o" "$L/crtn.o"
done
echo "built $OUT/ap_receiver ($(wc -c < "$OUT/ap_receiver") bytes)"
