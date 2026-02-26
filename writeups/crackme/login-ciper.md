# Login Cipher – Crackme Writeup

## Overview

This challenge provides a stripped 64-bit PIE ELF binary called `login`.
When executed, the program prints a warning message and asks for a password:

```
Don't patch it!
Insert your password:
```

Entering random value results in `Wrong!`, which suggests that the binary performs some internal transformation before validating the input.

The goal is to reverse the validation logic and recover the correct password.

---

## Initial Recon

Basic static inspection:

```bash
file login
strings login
```

Key observations:

* Dynamically linked ELF
* Stripped symbols
* Suspicious encoded strings such as:

```
Gtu.}'uj{fq!p{$
fhz4yhx|~g=5
Zwvup(
Ftyynjy*
```

These strongly indicate that the program applies a custom transformation to both UI strings and password logic.

---

## Dynamic Analysis

Using `ltrace`:

```bash
ltrace ./login
```

Output revealed:

```
__isoc99_scanf(...)
strcpy(...)
puts("Wrong!")
```

Notably:

* No calls to `strcmp`, `strncmp`, or `memcmp`.
* Therefore, the comparison is implemented manually inside the binary.

---

## Static Reversing (Ghidra)

The main logic resides inside `FUN_001012a1`:

```c
scanf("%64[^\n]", input);
result = FUN_001013e3(input, "fhz4yhx|~g=5");

if (result == 0)
    print("Ftyynjy*");
else
    print("Zwvup(");
```

So the password check is handled by:

```
FUN_001013e3(user_input, "fhz4yhx|~g=5")
```

---

## Understanding the Comparison Logic

### Function: `FUN_001013e3`

This function behaves like a custom `strcmp`, but instead of comparing against the seed string directly, it generates expected characters using another function:

```
FUN_00101175()
```

Pseudo-logic:

```
expected = gen(seed)
for each input_char:
    if input_char != expected:
        fail
    expected = gen(NULL)

success if both strings end simultaneously
```

Therefore:

* The seed `"fhz4yhx|~g=5"` is **not** the password.
* It is used to generate the real password.

---

## Generator Function Analysis

The generator maintains a global state:

```
state = 0x7b1
```

Each iteration:

```
state = (state * 7) % 65536
expected_char = seed_char - (state % 10)
```

So the algorithm is simply:

```
expected[i] = seed[i] - (state_i % 10)
```

---

## Recovering the Password

Seed string:

```
fhz4yhx|~g=5
```

Applying the transformation yields:

```
ccs-passwd44
```

Verification:

```bash
./login
```

```
Don't patch it!
Insert your password: ccs-passwd44
Correct!
```

---

## Notes on Encoded UI Strings

Functions like `FUN_00101348` copy encoded strings into a buffer and pass them through another routine before printing.

This explains why the binary contains obfuscated text such as:

```
Gtu.}'uj{fq!p{$
Zwvup(
Ftyynjy*
```

These are transformed at runtime into readable messages like:

```
Don't patch it!
Wrong!
Correct!
```

---

## Key Takeaways

* Lack of `strcmp` in `ltrace` is a strong hint of custom comparison logic.
* Many crackmes use seeded generators instead of storing plaintext passwords.
* When reversing validation routines, always locate:

  * the seed/source string
  * the state update rule
  * how expected bytes are produced

This challenge demonstrates a lightweight pseudo-cipher often seen in beginner reverse engineering exercises.

---

## Final Flag / Password

```
ccs-passwd44
```

---
