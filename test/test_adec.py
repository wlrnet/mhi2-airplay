#!/usr/bin/env python3
"""Correctness tests for the AAC decoder in ap_receiver (src/ap_adec.c + third_party/ffmpeg).

  python -I test_adec.py check <test_adec.exe> <datadir> <workdir>
      Regression test on ~1.2 s excerpts in test/data (ISO/IEC 14496-26 conformance bitstreams and
      the ISO reference decoder's PCM, as distributed in the FFmpeg FATE suite; see
      test/data/README.txt). Each excerpt is decoded and the S16 output must stay within +-2 of the
      reference (FATE's tolerance for these vectors) for every sample, cover the whole reference,
      and reach >= 60 dB SNR. Then 2000 random packets are fed to the AirPlay ELD preset (must not
      crash).
  python -I test_adec.py fate <test_adec.exe> <fatedir> <workdir> [ffmpeg.exe]
      Same check on the complete FATE samples (when downloaded) and, with an ffmpeg binary, the float
      output against that ffmpeg's own "aac" decoder.
"""
import math
import os
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# name, AudioSpecificConfig (hex, or ctN = the AirPlay preset), ISO reference channels, what it is
CASES = [
    ('eld480_48k_st', 'f8e65000', 2, 'AAC-ELD 480 stereo 48 kHz (AirPlay framing), er_eld2100np_48'),
    ('eld480_48k_st', 'ct8', 2, 'same stream through the AirPlay ct=8 preset (ASC f8e85000)'),
    ('eld512_48k_st', 'f8e64000', 2, 'AAC-ELD 512 stereo 48 kHz, er_eld2000np_48'),
    ('eld512_44k_mono', 'f8e82000', 1, 'AAC-ELD 512 mono 44.1 kHz, er_eld1001np_44'),
    ('lc_44k_mono', '12000504002001e000', 1, 'AAC-LC mono 44.1 kHz, al04_44'),
]
FATE = {
    'eld480_48k_st': ('er_eld2100np_48_ep0.mp4', 'er_eld2100np_48.s16'),
    'eld512_48k_st': ('er_eld2000np_48_ep0.mp4', 'er_eld2000np_48_ep0.s16'),
    'eld512_44k_mono': ('er_eld1001np_44_ep0.mp4', 'er_eld1001np_44.s16'),
    'lc_44k_mono': ('al04_44.mp4', 'al04_44.s16'),
}


def run(exe, asc, pkt, work, tag):
    f32 = os.path.join(work, tag + '.f32')
    s16 = os.path.join(work, tag + '.s16')
    out = subprocess.run([exe, asc, pkt, f32, s16], capture_output=True, text=True)
    info = dict(kv.split('=') for kv in out.stdout.split() if '=' in kv)
    return out.returncode, info, open(f32, 'rb').read(), open(s16, 'rb').read()


def compare_s16(ours_stereo, ref, ref_ch):
    """ours: interleaved stereo S16 from ap_adec_decode (mono is duplicated); ref: ISO S16."""
    n_ours = len(ours_stereo) // 4
    n_ref = len(ref) // (2 * ref_ch)
    n = min(n_ours, n_ref)
    a = struct.unpack('<%dh' % (2 * n), ours_stereo[:4 * n])
    b = struct.unpack('<%dh' % (ref_ch * n), ref[:2 * ref_ch * n])
    maxd = 0
    over = 0
    sig = err = 0.0
    for i in range(n):
        for c in range(ref_ch):
            x = a[2 * i + c]
            y = b[ref_ch * i + c]
            d = abs(x - y)
            if d > maxd:
                maxd = d
            if d > 2:
                over += 1
            sig += y * y
            err += (x - y) * (x - y)
    snr = 10 * math.log10(sig / err) if err else float('inf')
    return n, n_ours, n_ref, maxd, over, snr


def check(exe, data, work):
    os.makedirs(work, exist_ok=True)
    fails = 0
    for name, asc, ref_ch, what in CASES:
        tag = name + ('_' + asc if asc.startswith('ct') else '')
        rc, info, f32, s16 = run(exe, asc, os.path.join(data, name + '.pkt'), work, tag)
        ref = open(os.path.join(data, name + '.ref.s16'), 'rb').read()
        n, n_ours, n_ref, maxd, over, snr = compare_s16(s16, ref, ref_ch)
        ok = rc == 0 and n > 0 and n_ours == n_ref and over == 0 and snr >= 60.0
        print('%s %-22s %s: %s frames at %s Hz; vs ISO reference: max |diff| %d, samples off by >2: %d, SNR %.1f dB' % (
            'OK  ' if ok else 'FAIL', tag, what, info.get('frames'), info.get('rate'), maxd, over, snr))
        if not ok:
            fails += 1
    r = subprocess.run([exe, '--fuzz', '2000'], capture_output=True, text=True)
    ok = r.returncode == 0 and 'fuzz:' in r.stdout
    print('%s random packets into the ct=8 decoder: %s' % ('OK  ' if ok else 'FAIL', (r.stdout.strip() or 'crashed rc=%d' % r.returncode)))
    if not ok:
        fails += 1
    print('test_adec: %d checks, %d failed' % (len(CASES) + 1, fails))
    return 1 if fails else 0


def fate(exe, fatedir, work, ffmpeg=None):
    os.makedirs(work, exist_ok=True)
    fails = 0
    for name, asc, ref_ch, what in CASES:
        mp4, refname = FATE[name]
        pkt = os.path.join(work, name + '.full.pkt')
        asc_c = subprocess.run([sys.executable, '-I', os.path.join(HERE, 'mp4_packets.py'),
                                os.path.join(fatedir, mp4), pkt], capture_output=True, text=True).stdout.strip()
        use = asc if asc.startswith('ct') else asc_c
        tag = name + '_full' + ('_' + asc if asc.startswith('ct') else '')
        rc, info, f32, s16 = run(exe, use, pkt, work, tag)
        ref = open(os.path.join(fatedir, refname), 'rb').read()
        n, n_ours, n_ref, maxd, over, snr = compare_s16(s16, ref, ref_ch)
        line = '%-30s ours %d frames, ISO ref %d frames, compared %d: max |diff| %d, >2: %d, SNR %.1f dB' % (
            tag, n_ours, n_ref, n, maxd, over, snr)
        if ffmpeg:
            r = subprocess.run([ffmpeg, '-v', 'error', '-c:a', 'aac', '-i', os.path.join(fatedir, mp4),
                                '-f', 'f32le', '-'], capture_output=True)
            m = min(len(r.stdout), len(f32)) // 4
            a = struct.unpack('<%df' % m, f32[:4 * m])
            b = struct.unpack('<%df' % m, r.stdout[:4 * m])
            d = max(abs(x - y) for x, y in zip(a, b)) if m else 1.0
            line += '; vs ffmpeg "aac": %d samples, max |diff| %.2e (%.3f LSB of 16 bit)' % (m, d, d * 32768)
            if m == 0 or d * 32768 > 1.0:
                fails += 1
        if over or rc:
            fails += 1
        print(line)
    print('fate: %d failed' % fails)
    return 1 if fails else 0


if __name__ == '__main__':
    if sys.argv[1] == 'check':
        sys.exit(check(*sys.argv[2:5]))
    sys.exit(fate(*sys.argv[2:6]))
