# 🗺️ CTF Writeup — The Cursed Map (Forensics)

---

## 📖 Challenge Description

**Legend:**  
"Legend has it that there exists a map that leads to the greatest treasure of all, only the map is cursed so that anyone who opens it dies..."

**Provided File:** `map.pcap`

---

## 🔎 Initial Analysis

Upon opening `map.pcap` in Wireshark, the application immediately hangs or crashes.  
This explains the "curse" mentioned in the description — but what exactly is killing Wireshark?

We can open it safely by disabling:

Edit → Preferences → Protocols → HTTP → Uncompress entity bodies

Alternatively, inspecting traffic with lightweight tools like `tshark` or `tcpdump` reveals a suspicious HTTP transaction:

```http
HTTP
GET /flag.txt HTTP/1.1
Host: 10.11.157.174
Accept-Encoding: gzip, deflate, br

HTTP
HTTP/1.1 200 OK
Content-Type: text/plain
Content-Length: 860207
Content-Encoding: br
```

The server responds with an ~840KB Brotli-compressed payload.

Wireshark automatically attempts to decompress entity bodies — but this file is actually a **Decompression Bomb**.

The payload expands into enormous junk data, exhausting memory and crashing the program.

---

# 🧩 Step-by-Step Solution

---

## Step 1 — Extracting the Bomb

We must extract the raw compressed payload **without decompression**.

1. Locate the `HTTP/1.1 200 OK` response packet.
2. Expand the HTTP section.
3. Find the Brotli compressed payload.
4. Right-click → **Export Packet Bytes…**
5. Save as:

```
flag.br
```

---

## Step 2 — The Naive Approach (Why It Fails)

Attempting to decompress normally causes system failure.

### Attempt 1 — Writing to Disk

```bash
brotli -d flag.br
```

```
failed to write output [flag]: No space left on device
```

Reason:

The decompressed output is extremely large and fills the disk instantly.

---

### Attempt 2 — Grep in Memory

```bash
brotli -dc flag.br | grep -aoE 'BCCTF\{[^}]+\}'
```

```
zsh: killed grep ...
```

Reason:

`grep` buffers data line-by-line waiting for newline characters.

Decompression bombs often contain no newlines, causing massive RAM allocation until the Linux OOM killer terminates the process.

---

## Step 3 — Safe Extraction (Streaming & Chunking)

To safely extract the flag, we must enforce strict memory limits.

The idea:

- Stream decompression
- Process data in fixed chunks
- Prevent RAM explosion

---

### 1️⃣ Create `search.py`

```python
import sys
import re

def main():
    print("[*] Shield activated: Strictly limiting memory buffer...")
    tail = b''

    try:
        while True:
            chunk = sys.stdin.buffer.read(4096)
            if not chunk:
                break

            search_buffer = tail + chunk

            match = re.search(rb'BCCTF\{[^}]+\}', search_buffer)
            if match:
                print("\n[+] TREASURE FOUND:")
                print(match.group().decode('utf-8', errors='ignore'))
                sys.exit(0)

            tail = search_buffer[-100:]

    except KeyboardInterrupt:
        print("\n[-] Aborted by user.")
    except Exception as e:
        print(f"\n[!] Error: {e}")

if __name__ == '__main__':
    main()
```

---

### 2️⃣ Execute the Pipeline

```bash
brotli -dc flag.br | python3 search.py
```

Because OS pipes apply backpressure, Python controls the decompression rate — preventing CPU and RAM exhaustion.

---

# 🎉 Result

```
[+] TREASURE FOUND:
BCCTF{00H_1M_bR07l1_f33ls_S0_g0Od!}
```

---

## 🧠 Key Takeaways

- Never decompress unknown data blindly.
- Streaming processing defeats decompression bombs.
- Memory-bounded parsing is critical in forensic workflows.
