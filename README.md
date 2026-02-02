# SHELL-JS

A lightweight,shellcode loader written in js for Windows that reads shellcode from a local `.h` file (in `\xAA\xBB...` C-header format), allocates executable memory, and runs it in a new thread.

**Educational / Red Team / Research use only.**

## Features

- Reads shellcode from local file (**no network dependency**)
- Supports two input formats:
  - Classic C header style: `\xAA\xBB\xCC...` (`.h`, `.c`, `.txt`, etc.)
  - Raw binary shellcode (`.bin`, `.raw`, `.sc`)
- Optional **1-byte XOR decoding** with `--xor-key`
- Allocates memory using `VirtualAlloc`
- Attempts stealthier **RX** (PAGE_EXECUTE_READ) protection first
- Falls back to **RWX** (PAGE_EXECUTE_READWRITE) if RX fails
- Executes shellcode in a new thread via `CreateThread`
- Optional wait timeout for the thread (`--wait`) — supports non-blocking mode
- Clean help message with `--help` / `-h`
- Minimal dependencies (`koffi` + Node.js)


## Requirements

- Windows operating system
- Node.js ≥ 18
- npm

## Installation

```bash
# 1. Clone the repo
git clone https://github.com/00nx/shell-js.git
cd shell-js

# 2. Install dep
npm install koffi
```


## usage

```s
Usage: node inject.js <file> [options]
Options:
  --xor-key <number>   XOR decode shellcode with 1-byte key (0–255)
  --wait <ms>          WaitForSingleObject timeout (default: infinite, 0 = non-blocking)
  --help               Show this help
  ```
# Basic usage (C header file)
node inject.js payload.h

# Specify raw binary shellcode
node inject.js beacon.bin

# With XOR decoding (key = 0x5A)
node inject.js payload.h --xor-key 0x5A
node inject.js payload.bin -k 90

# Run and exit immediately (non-blocking)
node inject.js shellcode.bin --wait 0

# Wait max 10 seconds for thread to finish
node inject.js staged.bin --wait 10000

# Show help
node inject.js --help
   node inject.js bytes.h
   ```


