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

1. prepare the shell code with [donut](https://github.com/TheWover/donut) with proper flags ( must need C heade type -f 3 )
2. Run the loader
   ```bash
   node inject.js
   or
   node inject.js bytes.h
   ```


