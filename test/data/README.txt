AAC decoder test vectors (used by test/test_adec.py via test/run_tests.sh)

Each <name>.pkt holds the first ~1.2 s of access units of an ISO/IEC 14496-26 (MPEG-4 audio
conformance) bitstream, as [4-byte big-endian length][access unit] records (test/mp4_packets.py),
and <name>.ref.s16 the matching output of the ISO reference decoder (16-bit little-endian,
interleaved). Both come from the FFmpeg FATE suite (https://fate-suite.ffmpeg.org/aac/):

  eld480_48k_st     er_eld2100np_48_ep0.mp4 / er_eld2100np_48.s16     AAC-ELD, 480 samples/frame,
                    stereo, 48 kHz, no SBR -- the same framing as AirPlay mirroring audio
                    (ASC f8e65000 vs AirPlay's f8e85000: only the sample rate index differs)
  eld512_48k_st     er_eld2000np_48_ep0.mp4 / er_eld2000np_48_ep0.s16 AAC-ELD, 512, stereo, 48 kHz
  eld512_44k_mono   er_eld1001np_44_ep0.mp4 / er_eld1001np_44.s16     AAC-ELD, 512, mono, 44.1 kHz
  lc_44k_mono       al04_44.mp4 / al04_44.s16                         AAC-LC, mono, 44.1 kHz

Pass criterion (FATE's for these vectors): every output sample within +-2 of the reference.
Full-length check: python -I test/test_adec.py fate <test_adec.exe> <dir with the FATE files> <work> [ffmpeg]
