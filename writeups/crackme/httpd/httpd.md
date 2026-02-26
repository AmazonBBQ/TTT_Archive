# httpd (FreeBSD Go ELF) — Beginner Walkthrough: From Recon to Packet-Triggered Decryption

> **Goal**: Understand what the suspicious `httpd` binary does and extract the flag by reproducing its logic offline.

---

## Table of Contents

- [0) Recon: what is this binary and why won’t it run?](#0-recon-what-is-this-binary-and-why-wont-it-run)
  - [0.1 Files](#01-files)
  - [0.2 Identify platform](#02-identify-platform)
  - [0.3 Why Linux says “No such file or directory”】【#03-why-linux-says-no-such-file-or-directory)
- [1) First look in Ghidra: find the “obvious behavior”](#1-first-look-in-ghidra-find-the-obvious-behavior)
  - [1.1 Locate `main.main`](#11-locate-mainmain)
  - [1.2 A tiny HTTP server](#12-a-tiny-http-server)
  - [1.3 The handler is boring](#13-the-handler-is-boring)
- [2) Don’t brute-force `runtime.newproc`: use high-signal anchors](#2-dont-brute-force-runtimenewproc-use-high-signal-anchors)
- [3) Backtrack via crypto: find the real logic](#3-backtrack-via-crypto-find-the-real-logic)
  - [3.1 Pick “rare” crypto APIs](#31-pick-rare-crypto-apis)
  - [3.2 XREF `NewCBCDecrypter`](#32-xref-newcbcdecrypter)
- [4) Payload overview: sniff → match → derive key → decrypt → print](#4-payload-overview-sniff--match--derive-key--decrypt--print)
  - [4.1 Packet capture setup (pcap)](#41-packet-capture-setup-pcap)
  - [4.2 Trigger conditions (raw offsets)](#42-trigger-conditions-raw-offsets)
- [5) Extract the ciphertext (CT)](#5-extract-the-ciphertext-ct)
- [6) Recover key derivation (exact 16-byte layout)](#6-recover-key-derivation-exact-16-byte-layout)
- [7) Offline solver](#7-offline-solver)
- [8) What to remember for similar challenges](#8-what-to-remember-for-similar-challenges)
- [Final note](#final-note)

---

## 0) Recon: what is this binary and why won’t it run?

### 0.1 Files

We are given:

- `httpd` (binary)
- `README.md`: “found on an infected host”

### 0.2 Identify platform

```bash
file httpd

Observed traits:

ELF 64-bit for FreeBSD

interpreter: /libexec/ld-elf.so.1

Go BuildID + debug_info, not stripped

0.3 Why Linux says “No such file or directory”

On Linux, running it gives:

zsh: no such file or directory

strace: execve(...)= -1 ENOENT

This is a classic wrong-ABI symptom: Linux can’t execute a FreeBSD ELF, and the interpreter path (/libexec/ld-elf.so.1) doesn’t exist on Linux.

✅ Conclusion: Start with static analysis (Ghidra). Optionally run it later in a FreeBSD VM.

1) First look in Ghidra: find the “obvious behavior”
1.1 Locate main.main

Because it’s Go with debug info, you usually get useful names:

main.main

main.handler

many init functions

1.2 A tiny HTTP server

We quickly spot:

listens on :8080

registers route / → main.handler

prints Starting server...

At this stage it looks like a toy web server.

1.3 The handler is boring

main.handler(ResponseWriter, *Request) is also simple:

if Method == "GET": io.WriteString(w, s)

else: http.Error(...)

✅ Conclusion: The visible HTTP surface is decoy-ish and doesn’t explain “infected host”.

So: where’s the real payload?

2) Don’t brute-force runtime.newproc: use high-signal anchors

In Go binaries, scanning runtime.newproc is noisy (stdlib spawns goroutines everywhere).

A beginner-friendly approach:

pick one suspicious capability (crypto / pcap / exec / exfil)

follow references backwards to custom logic

Here we already saw gopacket strings (SSID-ish strings in .rodata), suggesting packet capture.
Also, “infected host” malware patterns often include:

sniffing traffic

decrypting only after a trigger packet

So we focus on pcap + crypto.

3) Backtrack via crypto: find the real logic
3.1 Pick “rare” crypto APIs

AES internals like aesCipher.Encrypt are too generic.

Instead, search higher-level API calls that appear less frequently:

crypto/aes.NewCipher

crypto/cipher.NewCBCDecrypter

crypto/cipher.(*cbcDecrypter).CryptBlocks

3.2 XREF NewCBCDecrypter

In Ghidra:

open crypto/cipher.NewCBCDecrypter

right-click → References / XREF

Instead of only standard library callers, we find a call path inside a function (often mislabeled as something init-ish like net/http.init). The important part is what it does:

calls pcap.OpenLive

loops over packets

constructs a key

decrypts a constant ciphertext

prints the plaintext

✅ This is the real payload.

4) Payload overview: sniff → match → derive key → decrypt → print
4.1 Packet capture setup (pcap)

Inside the init-like function:

pcap.OpenLive(device, snaplen=0x640, promisc=true, timeout=...)

handle.SetBPFFilter(...)

The filter string length is 4, strongly suggesting "icmp" (and behavior matches: it processes ICMP Echo packets).

Then it:

builds a gopacket.PacketSource

calls .Packets() to get a channel

uses chanrecv2 loop to receive packets

So: it’s a live sniffer.

4.2 Trigger conditions (raw offsets)

Before decrypting, it checks fixed offsets in the raw packet buffer (Ethernet + IPv4 assumed). Key checks:

pkt[0x22] == 0x08
ICMP Type == Echo Request

u16_le(pkt[0x26:0x28]) == 0x1337
ICMP Identifier

u16_be(pkt[0x10:0x12]) == 0x0020
IPv4 Total Length == 0x20

u32_le(pkt[0x2a:0x2e]) == 0xE55FDEC6
magic value inside ICMP data

Only if all are satisfied does the program proceed to decryption.

5) Extract the ciphertext (CT)

The code allocates a 32-byte buffer and fills it with four 64-bit constants.

Interpreting those qwords as little-endian bytes yields:

CT = bytes([
    0x51, 0xF1, 0xA5, 0x29, 0xB4, 0xDF, 0x7E, 0xC0,
    0x2A, 0x3B, 0x2F, 0x8F, 0x24, 0x3D, 0x4E, 0xB3,
    0x5A, 0xED, 0xB0, 0xCF, 0x0B, 0x9C, 0xDD, 0x8C,
    0xCD, 0xE6, 0x0E, 0x9B, 0x3E, 0xC4, 0x64, 0x0C
])

This is the ciphertext input to AES-CBC.

6) Recover key derivation (exact 16-byte layout)

This part becomes mechanical and beginner-friendly:

When you see assembly stores like MOV [RAX+0x8], EBX, you can map them directly:

key[8:12] = ...

From the stores, key layout is:

key[0:2] = bswap16( upper16(magic) XOR icmp_checksum_le )

key[2:6] = pkt[0x14:0x18] (4 bytes)

key[6:8] = pkt[0x24:0x26] (ICMP checksum bytes)

key[8:12] = pkt[0x2a:0x2e] (magic, little-endian)

key[12:14]= pkt[0x26:0x28] (ICMP id, little-endian)

key[14:16]= bswap16( icmp_checksum_le XOR lower16(magic) )

Then the binary calls:

aes.NewCipher(key)

cipher.NewCBCDecrypter(block, iv) where iv == key

CryptBlocks(pt, CT)

converts plaintext to string and prints it

So the flag is obtained by decrypting CT with AES-CBC using:

key = derived 16 bytes

iv = key

7) Offline solver

Below is a clean offline script that mirrors the binary’s CT + key layout.
It searches remaining degrees of freedom (TTL/seq/flags) until plaintext contains CMO{.
```
#!/usr/bin/env python3
from __future__ import annotations

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
    # ICMP Echo checksum over the word layout used by the challenge
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
        0xC6, 0xDE, 0x5F, 0xE5,  # MAGIC little-endian
        0x37, 0x13,              # ICMP ID little-endian
        xb & 0xFF, (xb >> 8) & 0xFF,
    ])


def main() -> None:
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
                    print("plaintext_str =", pt.decode("utf-8", errors="replace"))
                    return

    print("not found")


if __name__ == "__main__":
    main()
```
8) What to remember for similar challenges

Start with file: platform mismatch explains many “weird” runtime errors.

Identify decoys (banner / HTTP server) and confirm whether they matter.

Use high-signal anchors:

pcap / BPF → sniffers

aes / cbc / rsa → crypto payloads

exec / filesystem writes → persistence / execution

Backtrack with XREF from rare/high-level APIs (e.g., NewCBCDecrypter) into the true logic.

Translate assembly stores into data layouts (key[offset] = ...) for exact reproduction.

Write an offline solver: stable, reproducible, GitHub-friendly.
