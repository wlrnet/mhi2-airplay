# Changes to vendored third-party code

Everything under `third_party/` is upstream code as pinned in `third_party/VERSIONS.txt`,
except the changes listed here (GPLv3 §5a: modified files carry a notice in place, too).

| File | Change | Why |
|---|---|---|
| `third_party/uxplay/lib/mdnsd/mdnsd.c` (`mdnsd_start`) | Reads `AP_MDNS_ADDR` (IPv4 to answer with and to join the multicast group on) and `AP_MDNS_NO_IPV6=1` (no IPv6 socket/records). Without them behaviour is unchanged. | The head unit has several interfaces; the default-route address is not the hotspot the phone is on. |
| `third_party/libplist/libcnary/cnary.c` | Removed. | It is only a demo `main()`. |
| `third_party/uxplay/lib/crypto.c` | Kept but not built; replaced by `port/crypto_port.c`. | No OpenSSL on the car. |
