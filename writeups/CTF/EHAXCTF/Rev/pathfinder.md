# Pathfinder (EHAX) — Static Reverse Engineering Write‑up

> **Goal:** Recover the correct path string and the flag from the `pathfinder` binary using **pure static analysis** (Ghidra), then solve offline with a small Python script.

---

## 1. Recon

- The binary asks:
  - `Are you a pathfinder? [y/n]`
  - `Ok, tell me the best path:`
- If the input is correct, it prints:
  - `You have what it takes. Flag: ...`

In Ghidra, use **Search → For Strings** and follow XREFs to locate the main logic.

---

## 2. Locate the path checker

The input is stripped of the trailing newline with `strcspn`, then passed into a checker function (named by Ghidra like `FUN_00101444`).

High-level behavior of the checker:

- Start at `(r, c) = (0, 0)` on a **10×10** grid.
- For each character in the input:
  - Convert that character into a step `(dr, dc)` and two byte masks.
  - Reject moves that go out of bounds.
  - Reject moves that violate a per-cell bitmask constraint.
- At the end:
  - Must land exactly at `(9, 9)`.
  - Must satisfy a final **hash check**.

---

## 3. Understand the grid (map) construction

Ghidra shows a constructor-like init function (e.g. `_INIT_1`) that fills the grid `DAT_001040a0`:

```c
for (i = 0; i < 100; i++) {
  b1 = DAT_00102020[i];
  b2 = FUN_001011c9(i);
  DAT_001040a0[i] = b1 ^ b2;
}
```

And the mask function:

```c
uint FUN_001011c9(int i) {
  return (i << 3) ^ (i * 0x1f + 0x11U) ^ 0xffffffa5;
}
```

Because the grid is byte-sized, only the **low 8 bits** matter. The low byte of `0xffffffa5` is `0xA5`, so:

- `mask(i) = ((31*i + 0x11) ^ (8*i) ^ 0xA5) & 0xff`
- `grid[i] = rodata[i] ^ mask(i)`

The 100-byte source array `DAT_00102020` is in `.rodata` (offset `0x2020` in this challenge).

---

## 4. Recover valid moves (N/S/E/W) from `_INIT_2`

The checker appears to use large tables `DAT_00104120/28`, but they live in `.bss` and are initially zero.
A second init function (e.g. `_INIT_2`) does:

- `memset(&DAT_00104120, 0, 0xC00);`
- then writes **only a few entries**, which makes the table **sparse**.

You can map the write addresses back to characters using:

- Entry size = `0xC` bytes per character.
- Base = `DAT_00104120 = 0x00104120`.
- `ch = (addr - base) / 0xC`.

This reveals only four valid characters: **`N`, `S`, `E`, `W`**, each with:

- a move `(dr, dc)`
- two “permission bytes” (`p0`, `p1`) used to build masks.

Recovered entries:

| Char | dr | dc | p0  | p1  |
|------|----|----|-----|-----|
| N    | -1 |  0 | A2  | A7  |
| S    | +1 |  0 | 8C  | 89  |
| E    |  0 | +1 | E9  | E3  |
| W    |  0 | -1 | 69  | 63  |

---

## 5. Per-step constraint

Each move computes two byte masks:

- `mul = (ord(ch) * 0x6B) & 0xFF`
- `k1 = (mul ^ p0 ^ 0x3C) & 0xFF`
- `k2 = (mul ^ p1 ^ 0x3C) & 0xFF`

Then checks the grid “cell masks”:

```c
ok = ((cell(r,c) & k1) | (cell(nr,nc) & k2)) != 0
```

The cell accessor in the working coordinate system is:

- `cell(r,c) = grid[r*10 + c]`

---

## 6. Final hash check

The checker ends with a deterministic hash function (Ghidra like `FUN_0010126b`) and compares to:

- Target = `0x86BA520C`

We can reimplement it exactly:

1. Start `h = 0xDEADBEEF`
2. For each byte `b` in the path:
   - `h ^= b`
   - rotate-left 13
   - multiply by `0x045D9F3B`
3. Final mix:
   - `h ^= h >> 16`
   - multiply by `0x85EBCA6B` (which equals `(-0x7A143595) mod 2^32`)
   - `h ^= h >> 13`

---

## 7. Offline solving strategy

A key observation: **Don’t BFS on the 32-bit hash state** (state-space explodes).
Instead:

- BFS on **position only**, keeping the shortest path reaching each cell.
- When you reach `(9,9)`, validate with the hash.

This is fast because:
- grid is only 10×10
- there are only 4 directions

---

## 8. Solver (Python)

Save as `solve.py`:

```python
from collections import deque

RO = [
    0xBC, 0x97, 0xF6, 0xD3, 0x08, 0x21, 0x5E, 0x77,
    0xEC, 0xC5, 0xB2, 0x9B, 0x45, 0x69, 0x16, 0x37,
    0x2E, 0x07, 0x06, 0x63, 0x78, 0x91, 0xAD, 0xC7,
    0x9C, 0x70, 0x42, 0x2B, 0x35, 0xD9, 0xEE, 0x85,
    0x5E, 0xB7, 0x90, 0xF2, 0xE8, 0x01, 0x3B, 0x57,
    0x09, 0xE5, 0xD2, 0xBB, 0xA0, 0x49, 0x7E, 0x15,
    0xC5, 0x2D, 0x2F, 0x03, 0x54, 0x7B, 0x82, 0xA7,
    0xB9, 0x95, 0x62, 0x4B, 0x15, 0x39, 0xC3, 0xEF,
    0x71, 0x5D, 0xBF, 0x93, 0xC8, 0xE1, 0x1B, 0x37,
    0x2D, 0x05, 0xF1, 0xD1, 0x89, 0xA9, 0x5E, 0x73,
    0xE1, 0xCD, 0xCA, 0x23, 0x38, 0x51, 0x6E, 0x87,
    0xD9, 0xB0, 0x81, 0x61, 0x7A, 0x13, 0x2C, 0xC5,
    0x1E, 0x77, 0x5B, 0xB0,
]

def build_grid(ro):
    out = []
    for i in range(100):
        a = (31 * i + 0x11) & 0xFFFFFFFF
        b = (8 * i) & 0xFFFFFFFF
        m = (a ^ b ^ 0xA5) & 0xFF
        out.append((ro[i] ^ m) & 0xFF)
    return out

ARR = build_grid(RO)

def cell(r, c):
    return ARR[r * 10 + c]

DIRS = {
    'N': {'dr': -1, 'dc': 0, 'p0': 0xA2, 'p1': 0xA7},
    'S': {'dr': +1, 'dc': 0, 'p0': 0x8C, 'p1': 0x89},
    'E': {'dr':  0, 'dc': +1, 'p0': 0xE9, 'p1': 0xE3},
    'W': {'dr':  0, 'dc': -1, 'p0': 0x69, 'p1': 0x63},
}

def kvals(ch: str):
    mul = (ord(ch) * 0x6B) & 0xFF
    d = DIRS[ch]
    k1 = (mul ^ d['p0'] ^ 0x3C) & 0xFF
    k2 = (mul ^ d['p1'] ^ 0x3C) & 0xFF
    return k1, k2

def rol32(x, r):
    return ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF

def path_hash(s: str) -> int:
    h = 0xDEADBEEF
    for ch in s.encode():
        h ^= ch
        h = rol32(h, 13)
        h = (h * 0x045D9F3B) & 0xFFFFFFFF
    h ^= (h >> 16)
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= (h >> 13)
    return h & 0xFFFFFFFF

TARGET = 0x86BA520C

def solve():
    q = deque([(0, 0, '')])
    best_len = [[None] * 10 for _ in range(10)]
    best_len[0][0] = 0

    while q:
        r, c, s = q.popleft()
        if (r, c) == (9, 9):
            if path_hash(s) == TARGET:
                return s
            continue

        for ch in 'NSEW':
            d = DIRS[ch]
            nr, nc = r + d['dr'], c + d['dc']
            if not (0 <= nr <= 9 and 0 <= nc <= 9):
                continue
            k1, k2 = kvals(ch)
            if ((cell(r, c) & k1) | (cell(nr, nc) & k2)) == 0:
                continue
            ns = s + ch
            bl = best_len[nr][nc]
            if bl is None or len(ns) < bl:
                best_len[nr][nc] = len(ns)
                q.append((nr, nc, ns))
    return None

def rle_flag(path: str) -> str:
    out = ['EHAX{']
    i = 0
    while i < len(path):
        j = i
        while j < len(path) and path[j] == path[i]:
            j += 1
        run = j - i
        out.append(f"{run}{path[i]}" if run > 1 else path[i])
        i = j
    out.append('}')
    return ''.join(out)

if __name__ == '__main__':
    p = solve()
    print("Path:", p)
    print("Flag:", rle_flag(p))
```

---

## 9. Result

Running the solver yields:

- **Path:** `EESSSWWSSSSSSEEEEEEEENNESS`
- **Flag:** `EHAX{2E3S2W6S8E2NE2S}`

---

## Notes

- The “large table” is **sparse**: it is zeroed with `memset`, then only a handful of entries are written (N/S/E/W).
- The grid is fully deterministic: `.rodata` bytes XOR a simple arithmetic mask, so no dynamic debugging is required.
