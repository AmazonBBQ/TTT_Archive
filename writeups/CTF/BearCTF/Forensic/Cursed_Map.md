# CTF Writeup: The Cursed Map (Forensics)

**📖 Challenge Description**

Legend: "Legend has it that there exists a map that leads to the greatest treasure of all, only the map is cursed so that anyone who opens it dies..."
Provided File: map.pcap

**Initial Analysis**

Upon opening map.pcap in Wireshark, the application immediately hangs or crashes. This explains the "curse" mentioned in the description. But what exactly is killing Wireshark?

We could open it by unselecting the Edit -> Preferences -> Protocols -> HTTP -> Uncompress entity bodies. Also if we inspect the traffic using a lightweight tool like tshark or tcpdump, we can spot a highly suspicious HTTP transaction:
```
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

The server responds with an ~840KB file compressed using the Brotli (br) algorithm. By default, Wireshark attempts to automatically decompress HTTP entity bodies to display the plaintext.

However, this is not a normal file—it is a Decompression Bomb (Brotli Bomb). The 840KB payload expands to dozens or hundreds of gigabytes of junk data. When Wireshark attempts to decompress it in memory, it instantly exhausts system resources and crashes.

**Step-by-Step Solution**

Step 1: Extracting the Bomb

We need to extract the raw, compressed payload without letting any program decompress it yet.

Locate the HTTP/1.1 200 OK response packet.

In the Packet Details pane, expand the HTTP section and find the actual data payload (Brotli compressed data).

Right-click the data node and select Export Packet Bytes....

Save the file as flag.br.

Step 2: The Naive Approach (And Why It Fails)

If we try to decompress this file normally, we hit a wall:

Attempt 1: Writing to disk
```
$ brotli -d flag.br
failed to write output [flag]: No space left on device
Reason: The decompressed file is too massive. It instantly fills up the hard drive.
```
Attempt 2: Piping to grep in memory
```
$ brotli -dc flag.br | grep -aoE 'BCCTF\{[^}]+\}'
zsh: killed      grep --color=auto -aoE 'BCCTF\{[^}]+\}'
```

Reason: grep reads text line-by-line, looking for newline (\n) characters. A decompression bomb is typically filled with endless NULL bytes or spaces without a single newline. grep ends up buffering gigabytes of data into RAM trying to find a complete "line", triggering the Linux OOM (Out Of Memory) killer.

Step 3: The Safe Extraction (Streaming & Chunking)

To defeat the bomb, we must enforce a strict memory limit. We can use the system's brotli command to decompress the stream, pipe it (|), and use a Python script to ingest the stream in fixed 4KB chunks.

Because of how OS pipes work, if Python reads the data slowly, the OS will block the brotli process from decompressing further, preventing both CPU and RAM exhaustion.

1. Create search.py:

```
import sys
import re

def main():
    print("[*] Shield activated: Strictly limiting memory buffer...")
    tail = b''
    
    try:
        # Read directly from the raw binary standard input
        while True:
            # Strictly limit reading to 4KB chunks
            chunk = sys.stdin.buffer.read(4096)
            if not chunk:
                break
            
            # Append previous tail to handle edge cases where the flag spans across chunks
            search_buffer = tail + chunk
            
            match = re.search(rb'BCCTF\{[^}]+\}', search_buffer)
            if match:
                print("\n[+] TREASURE FOUND:")
                print(match.group().decode('utf-8', errors='ignore'))
                sys.exit(0)
                
            # Keep the last 100 bytes for the next iteration
            tail = search_buffer[-100:]
            
    except KeyboardInterrupt:
        print("\n[-] Aborted by user.")
    except Exception as e:
        print(f"\n[!] Error: {e}")

if __name__ == '__main__':
    main()
```

2. Execute the Pipeline:

```
brotli -dc flag.br | python3 search.py
```
**🎉 Result**

[+] TREASURE FOUND:
BCCTF{00H_1M_bR07l1_f33ls_S0_g0Od!}
