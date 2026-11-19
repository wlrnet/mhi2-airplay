# mhi2-airplay

An AirPlay screen-mirroring receiver for MIB2 High (MHI2) head units, which run QNX 6.5 on
ARMv7. An iPhone on the head unit's Wi-Fi can pick it in **Screen Mirroring**.

This repository is the complete source of the `ap_receiver` program, published under the
GNU General Public License v3 because it is based on [UxPlay](https://github.com/FDH2/UxPlay).

## What `ap_receiver` does

- Speaks AirPlay mirroring using UxPlay's `lib/`. This covers pairing, the mirroring handshake,
  the RTSP session, the encrypted H.264 stream and the audio stream.
- Announces `_airplay._tcp` and `_raop._tcp` with UxPlay's built-in mDNS responder, on one chosen
  interface address only.
- Decodes the mirroring audio (AAC-ELD) to PCM.
- Sends the H.264 access units and the PCM to external output processes on `127.0.0.1`. Their
  wire formats are described in `src/ap_video_link.h` and the audio link header. Those output
  processes are not part of this program.
- Does not use OpenSSL. The cryptography is mbedTLS plus Monocypher behind UxPlay's `crypto.h`
  (`port/crypto_port.c`), with a small OpenSSL-compatible BIGNUM/EVP layer (`port/ossl/`) so
  UxPlay's `srp.c` builds unchanged.

## Layout

| Path | Contents |
|---|---|
| `src/` | `ap_receiver` main program, video link, audio decoding and link |
| `port/` | QNX 6.5 compatibility, crypto backend, mbedTLS config, decoder build config |
| `third_party/` | UxPlay `lib/`, libplist, mbedTLS, Monocypher, the FFmpeg AAC decoder subset. Versions are in `third_party/VERSIONS.txt` and local changes in `port/PATCHES.md`. |
| `test/` | PC tests: crypto known-answer vectors, BIGNUM against Python, frame splitting, audio decoding |
| `LICENSES/` | GPL-3.0 text and third-party licences |

## Build

You need:

- [zig](https://ziglang.org) 0.16.0, used as the C compiler and linker.
- The QNX 6.5 SDP target tree (`target/qnx6`: `usr/include` and `armle-v7/lib`). It is
  commercial software and is not included here.

```sh
export ZIG=/path/to/zig QNX=/path/to/qnx650/target/qnx6
sh build.sh                 # -> build/qnx/ap_receiver (and .unstripped)
sh test/run_tests.sh        # PC tests; needs ZIG and python
```

The binary depends only on `libc.so.3`, `libsocket.so.3` and `libm.so.2`.

## Runtime configuration (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `AP_NAME` | first line of `/mnt/persist/airplay_name`, else `MIB` | Name shown on the iPhone |
| `AP_IFNAME` / `AP_IFADDR` | `uap0` / looked up | Interface (or IPv4) to serve and announce on |
| `AP_DATA` | `/mnt/persist/airplay` | Device id and pairing key |
| `AP_VIDEO_PORT` | `7111` | Video output process on 127.0.0.1 |
| `AP_WIDTH` / `AP_HEIGHT` / `AP_FPS` | `1280` / `640` / `30` | Display size and frame rate told to the phone |
| `AP_PORT` | `7000` | RTSP port. Mirroring data uses TCP 7100; timing, control and audio use UDP 7011–7013. |

There is no PIN or password. Anyone who can reach the head unit's Wi-Fi can mirror to it.

## License

GPL-3.0-or-later; see `LICENSES/GPL-3.0.txt`. Third-party components keep their own licences
(`LICENSES/THIRD_PARTY_LICENSES.txt`):

- UxPlay: GPL-3.0-or-later
- libplist: LGPL-2.1-or-later
- mbedTLS: Apache-2.0
- Monocypher: BSD-2-Clause / CC0
- FFmpeg: LGPL-2.1-or-later

This project is not affiliated with Apple. "AirPlay" and "iPhone" are trademarks of Apple Inc.
