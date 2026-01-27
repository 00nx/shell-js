# SHELL-JS

A lightweight,shellcode loader written in js for Windows that reads shellcode from a local `.h` file (in `\xAA\xBB...` C-header format), allocates executable memory, and runs it in a new thread.

**Educational / Red Team / Research use only.**

## Features

- Reads shellcode from a local file (no network dependency)
- Parses classic `\xAA\xBB\xCC` C-style byte arrays
- Allocates memory using `VirtualAlloc`
- Attempts stealthier **RX** memory protection first, with fallback to **RWX**
- Executes shellcode in a new thread via `CreateThread`
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


