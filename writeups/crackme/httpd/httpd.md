# httpd (FreeBSD Go ELF) — Packet-triggered AES-CBC Decryption (Write-up)

## TL;DR
The binary masquerades as a harmless `httpd` listening on `:8080`, but its real logic is a packet sniffer:
it captures ICMP packets via `pcap`, checks for a specific “magic” Echo Request, derives a 16-byte AES key from
selected header fields, decrypts a hard-coded 32-byte ciphertext using AES-CBC (IV = key), and prints the plaintext
(flag) to stdout.

---

## 1. Initial Triage
### 1.1 Why it does not run on Linux
`file httpd` reports a **FreeBSD** ELF with interpreter `/libexec/ld-elf.so.1`.  
Linux cannot execute FreeBSD binaries, so `execve()` fails with `ENOENT`.

### 1.2 Quick hints from metadata
- Go binary with debug info (not stripped): easy to follow symbols in Ghidra.
- Imports include `github.com/google/gopacket/pcap` / `gopacket/layers` → likely packet capture / protocol parsing.

---

## 2. The Decoy: HTTP Server
In `main.main` the program starts a server on `:8080` and registers exactly one route:
- `HandleFunc("/", main.handler)`

`main.handler` is intentionally boring:
- If `r.Method == "GET"` it writes a fixed string to the response.
- Otherwise it calls `http.Error`.

This is a distraction. The real payload is not in the HTTP handler.

---

## 3. The Real Payload: Sniff → Match → Decrypt (in init)
The interesting code is executed during initialization (observed in the function labeled `net/http.init` by Ghidra).
It performs the following steps:

### 3.1 Open a live capture and set a BPF filter
- `pcap.OpenLive(device, snaplen=0x640, promisc=true, timeout=...)`
- `handle.SetBPFFilter("icmp")` (length 4 strongly indicates `"icmp"`)

Then it creates a `gopacket.PacketSource`, calls `.Packets()`, and receives packets in a loop from a channel.

### 3.2 Packet trigger conditions
The code checks raw packet bytes at fixed offsets (Ethernet + IPv4 assumed) and requires:

- `pkt[0x22] == 0x08`  
  ICMP type = Echo Request
- `u16(pkt[0x26:0x28], little) == 0x1337`  
  ICMP identifier
- `u16(pkt[0x10:0x12], big) == 0x0020`  
  IPv4 total length == 0x20
- `u32(pkt[0x2a:0x2e], little) == 0xE55FDEC6`  
  4-byte “magic” payload marker

Only if all conditions match does decryption occur.

---

## 4. Cryptography: AES-CBC with IV = key
### 4.1 Hard-coded ciphertext (CT)
A 32-byte buffer is allocated and filled with four 64-bit constants, which form the ciphertext.
Interpreting each constant as little-endian bytes yields:

```python
CT = bytes([
    0x51, 0xF1, 0xA5, 0x29, 0xB4, 0xDF, 0x7E, 0xC0,
    0x2A, 0x3B, 0x2F, 0x8F, 0x24, 0x3D, 0x4E, 0xB3,
    0x5A, 0xED, 0xB0, 0xCF, 0x0B, 0x9C, 0xDD, 0x8C,
    0xCD, 0xE6, 0x0E, 0x9B, 0x3E, 0xC4, 0x64, 0x0C
])
4.2 Key derivation (16 bytes)

Assembly shows the key is constructed by writing specific fields into fixed offsets:

key[0:2] = bswap16(upper16(magic) XOR icmp_checksum_le)

key[2:6] = pkt[0x14:0x18] (4 bytes)

key[6:8] = pkt[0x24:0x26] (ICMP checksum bytes)

key[8:12] = pkt[0x2a:0x2e] (magic, little-endian)

key[12:14]= pkt[0x26:0x28] (ICMP id, little-endian)

key[14:16]= bswap16(icmp_checksum_le XOR lower16(magic))

Then:

aes.NewCipher(key)

cipher.NewCBCDecrypter(block, iv) where len(iv)=16 and iv is derived from the same key bytes (IV = key)

CryptBlocks(pt, CT)

pt is converted to string and printed.

5. Offline Solver (Extract Flag)

The following script brute-forces the remaining degrees of freedom (TTL/seq/flags) and prints the decrypted plaintext
once it contains the expected flag prefix.

Note: This exactly mirrors the binary’s key layout and ciphertext.

#!/usr/bin/env python3
import struct

try:
    from Crypto.Cipher import AES
    def aes_cbc_dec(key: bytes, ct: bytes) -> bytes:
        return AES.new(key, AES.MODE_CBC, iv=key).decrypt(ct)
except ImportError:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    def aes_cbc_dec(key: bytes, ct: bytes) -> bytes:
        c = Cipher(algorithms.AES(key), modes.CBC(key))
        d = c.decryptor()
        return d.update(ct) + d.finalize()

CT = bytes([
    0x51, 0xF1, 0xA5, 0x29, 0xB4, 0xDF, 0x7E, 0xC0,
    0x2A, 0x3B, 0x2F, 0x8F, 0x24, 0x3D, 0x4E, 0xB3,
    0x5A, 0xED, 0xB0, 0xCF, 0x0B, 0x9C, 0xDD, 0x8C,
    0xCD, 0xE6, 0x0E, 0x9B, 0x3E, 0xC4, 0x64, 0x0C
])

MAGIC = 0xE55FDEC6
UPPER16 = (MAGIC >> 16) & 0xFFFF
LOWER16 = MAGIC & 0xFFFF

def bswap16(x: int) -> int:
    return ((x & 0xFF) << 8) | ((x >> 8) & 0xFF)

def icmp_checksum(seq: int) -> int:
    # Echo Request checksum over 16-bit words (layout used by the challenge)
    s = 0x0800 + 0x3713 + (seq & 0xFFFF) + 0xC6DE + 0x5FE5
    while s > 0xFFFF:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

def build_key(flags_hi: int, flags_lo: int, ttl: int, seq: int) -> bytes:
    ck = icmp_checksum(seq)
    ck_b0 = (ck >> 8) & 0xFF
    ck_b1 = ck & 0xFF
    ck_le = ck_b0 | (ck_b1 << 8)

    xa = bswap16((UPPER16 ^ ck_le) & 0xFFFF)
    xb = bswap16((ck_le ^ LOWER16) & 0xFFFF)

    return bytes([
        xa & 0xFF, (xa >> 8) & 0xFF,
        flags_hi & 0xFF, flags_lo & 0xFF, ttl & 0xFF, 0x01,  # proto=ICMP
        ck_b0, ck_b1,
        0xC6, 0xDE, 0x5F, 0xE5,  # MAGIC (little-endian)
        0x37, 0x13,              # ICMP ID (little-endian)
        xb & 0xFF, (xb >> 8) & 0xFF,
    ])

def main():
    flag_opts = [(0x00, 0x00), (0x40, 0x00)]  # no DF vs DF

    for fh, fl in flag_opts:
        for ttl in range(256):
            for seq in range(0x10000):
                key = build_key(fh, fl, ttl, seq)
                pt = aes_cbc_dec(key, CT)
                if b"CMO{" in pt:
                    print("FOUND!")
                    print("flags/frag =", hex((fh << 8) | fl), "ttl =", ttl, "seq =", seq)
                    print("key =", key.hex())
                    print("plaintext =", pt)
                    try:
                        print("plaintext_str =", pt.decode("utf-8", errors="replace"))
                    except Exception:
                        pass
                    return

    print("not found")

if __name__ == "__main__":
    main()
6. Notes / Takeaways

Don’t be distracted by benign-looking services (the HTTP server here is a decoy).

In Go malware-like CTF binaries, the “real” logic often lives in init() paths.

Use high-signal anchors (pcap, exec, crypto) + XREF backtracking to quickly land on the payload.

Once the trigger condition and key layout are recovered, an offline solver is usually the cleanest way to extract the flag.
