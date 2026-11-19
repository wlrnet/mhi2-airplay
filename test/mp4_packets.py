#!/usr/bin/env python3
"""Extract the first audio track of an MP4 as raw access units for test_adec.

Usage: python mp4_packets.py <in.mp4> <out.pkt>
Writes out.pkt = repeated [4-byte big-endian length][access unit] and prints the track's
AudioSpecificConfig (from esds) as hex on stdout. Only what the FATE AAC samples need:
stsd/mp4a/esds, stsz, stsc, stco/co64; no fragments, no edit lists.
"""
import struct
import sys


def boxes(buf, off, end):
    while off + 8 <= end:
        size, typ = struct.unpack('>I4s', buf[off:off + 8])
        hdr = 8
        if size == 1:
            size = struct.unpack('>Q', buf[off + 8:off + 16])[0]
            hdr = 16
        elif size == 0:
            size = end - off
        if size < hdr:
            raise ValueError('bad box size')
        yield typ.decode('latin-1'), off + hdr, off + size
        off += size


def find(buf, off, end, path):
    for typ, s, e in boxes(buf, off, end):
        if typ == path[0]:
            if len(path) == 1:
                return s, e
            r = find(buf, s, e, path[1:])
            if r:
                return r
    return None


def desc_len(buf, p):
    n = 0
    for _ in range(4):
        b = buf[p]
        p += 1
        n = (n << 7) | (b & 0x7f)
        if not b & 0x80:
            break
    return n, p


def asc_from_esds(buf, s, e):
    p = s + 4                      # version/flags
    while p < e:
        tag = buf[p]
        n, p = desc_len(buf, p + 1)
        if tag == 0x03:            # ES_Descriptor
            flags = buf[p + 2]
            p += 3
            if flags & 0x80: p += 2
            if flags & 0x40: p += 1 + buf[p]
            if flags & 0x20: p += 2
            continue
        if tag == 0x04:            # DecoderConfigDescriptor
            p += 13
            continue
        if tag == 0x05:            # DecoderSpecificInfo = AudioSpecificConfig
            return buf[p:p + n]
        p += n
    raise ValueError('no AudioSpecificConfig')


def main():
    buf = open(sys.argv[1], 'rb').read()
    moov = find(buf, 0, len(buf), ['moov'])
    for typ, s, e in boxes(buf, *moov):
        if typ != 'trak':
            continue
        hdlr = find(buf, s, e, ['mdia', 'hdlr'])
        if not hdlr or buf[hdlr[0] + 8:hdlr[0] + 12] != b'soun':
            continue
        stbl = find(buf, s, e, ['mdia', 'minf', 'stbl'])
        stsd = find(buf, *stbl, ['stsd'])
        # stsd: version/flags(4) count(4), then the mp4a sample entry (28 bytes of fields) + children
        entry_s = stsd[0] + 8
        entry_size = struct.unpack('>I', buf[entry_s:entry_s + 4])[0]
        esds = find(buf, entry_s + 8 + 28, entry_s + entry_size, ['esds'])
        asc = asc_from_esds(buf, *esds)
        s0, _ = find(buf, *stbl, ['stsz'])
        fixed, count = struct.unpack('>II', buf[s0 + 4:s0 + 12])
        sizes = [fixed] * count if fixed else list(struct.unpack('>%dI' % count, buf[s0 + 12:s0 + 12 + 4 * count]))
        s1, _ = find(buf, *stbl, ['stsc'])
        n = struct.unpack('>I', buf[s1 + 4:s1 + 8])[0]
        stsc = [struct.unpack('>III', buf[s1 + 8 + 12 * i:s1 + 20 + 12 * i]) for i in range(n)]
        co = find(buf, *stbl, ['stco'])
        if co:
            m = struct.unpack('>I', buf[co[0] + 4:co[0] + 8])[0]
            chunks = list(struct.unpack('>%dI' % m, buf[co[0] + 8:co[0] + 8 + 4 * m]))
        else:
            co = find(buf, *stbl, ['co64'])
            m = struct.unpack('>I', buf[co[0] + 4:co[0] + 8])[0]
            chunks = list(struct.unpack('>%dQ' % m, buf[co[0] + 8:co[0] + 8 + 8 * m]))
        out = open(sys.argv[2], 'wb')
        k = 0
        for ci, coff in enumerate(chunks):
            per = 0
            for first, spc, _ in stsc:
                if ci + 1 >= first:
                    per = spc
            for _ in range(per):
                if k >= count:
                    break
                out.write(struct.pack('>I', sizes[k]) + buf[coff:coff + sizes[k]])
                coff += sizes[k]
                k += 1
        out.close()
        print(asc.hex())
        return 0
    raise SystemExit('no audio track')


if __name__ == '__main__':
    sys.exit(main())
