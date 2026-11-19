"""Differential test: BIGNUM shim (port/ossl/ossl_compat.c) against Python integers.

Usage: python -I test_bn.py <path-to-bn_calc.exe>
Covers the operations UxPlay's srp.c uses, with the SRP 2048-bit group modulus included.
"""
import random
import subprocess
import sys

# RFC 5054 2048-bit group (SRP_NG_2048, the group UxPlay uses)
N2048 = int(
    "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4"
    "A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF60"
    "95179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF"
    "747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B907"
    "8717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB37861"
    "60279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DB"
    "FBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73", 16)


def h(x):
    return format(x, "x")


def main():
    exe = sys.argv[1]
    rnd = random.Random(20261119)
    cases = []

    def rint(bits):
        return rnd.getrandbits(rnd.randint(1, bits))

    mods = [N2048, (1 << 127) - 1, 0xFFFFFFFB, (1 << 521) - 1]
    for _ in range(150):
        a, b = rint(2100), rint(2100)
        cases.append(("add", a, b, 1, a + b))
        if a >= b:
            cases.append(("sub", a, b, 1, a - b))
        cases.append(("mul", a, b, 1, a * b))
        m = rnd.choice(mods)
        cases.append(("mod", a, 0, m, a % m))
        cases.append(("modadd", a % m, b % m, m, (a + b) % m))
        cases.append(("modmul", a, b, m, (a * b) % m))
        e = rint(512)
        cases.append(("modexp", a, e, m, pow(a, e, m)))
        cases.append(("modexp_alias", b, e, m, pow(b, e, m)))
    # edge values
    for m in mods:
        cases.append(("modexp", 2, 0, m, 1))
        cases.append(("modexp", 0, 5, m, 0))
        cases.append(("modexp", m + 3, 2, m, 9 % m))
        cases.append(("mod", m, 0, m, 0))
    cases.append(("add", 0, 0, 1, 0))
    cases.append(("mul", 0, 12345, 1, 0))
    cases.append(("add", 0xFF, 1, 1, 0x100))
    cases.append(("sub", 0x100, 1, 1, 0xFF))

    lines = "".join("%s %s %s %s\n" % (op, h(a), h(b), h(m)) for op, a, b, m, _ in cases)
    rand_lines = "".join("rand %d 0 1\n" % bits for bits in (32, 128, 256, 1000) for _ in range(20))
    out = subprocess.run([exe], input=lines + rand_lines, capture_output=True, text=True, check=True).stdout.split()

    fail = 0
    for (op, a, b, m, want), got in zip(cases, out):
        if got == "ERR" or int(got, 16) != want:
            fail += 1
            if fail <= 5:
                print("FAIL %s a=%s.. b=%s.. m=%s.. got %s.. want %s.." % (op, h(a)[:16], h(b)[:16], h(m)[:16], got[:24], h(want)[:24]))
    rand_out = out[len(cases):]
    seen = set()
    k = 0
    for bits in (32, 128, 256, 1000):
        for _ in range(20):
            v = int(rand_out[k], 16)
            k += 1
            if v >> bits:
                fail += 1
                print("FAIL rand %d bits produced %d bits" % (bits, v.bit_length()))
            seen.add((bits, v))
    if len(seen) < 79:   # 80 draws; a repeat of a 32-bit value is possible but unlikely
        fail += 1
        print("FAIL rand repeats: %d distinct of 80" % len(seen))
    if len(out) != len(cases) + 80:
        fail += 1
        print("FAIL output count %d, expected %d" % (len(out), len(cases) + 80))
    print("test_bn: %d cases, %d failed" % (len(cases) + 80, fail))
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
