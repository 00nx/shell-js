// ═══════════════════════════════════════════════════════════════════════════
//  shellcode-runner.js
//
//  Loads shellcode from a raw binary or `\xNN` hex-text file, optionally
//  XOR-decodes it, reports static analysis, and (on Windows) executes it
//  inside a freshly-allocated RX page via a worker thread.
//
//  Usage: node shellcode-runner.js <file> [options]     (see --help)
// ═══════════════════════════════════════════════════════════════════════════

'use strict';

const fs     = require('fs').promises;
const path   = require('path');
const crypto = require('crypto');
const koffi  = require('koffi');


// ═══════════════════════════════════════════════════════════════════════════
//  Configuration
// ═══════════════════════════════════════════════════════════════════════════

const CONFIG = Object.freeze({
  DEFAULT_MAX_FILE_SIZE : 10 * 1024 * 1024,      // 10 MiB
  RAW_EXTENSIONS        : ['.bin', '.raw', '.sc', '.shellcode', '.dat'],
  HEX_EXTENSIONS        : ['.txt', '.h', '.c', '.hex', '.bytes'],
  ALLOWED_FORMATS       : ['auto', 'raw', 'hex'],
  PROBE_PRINTABLE_RATIO : 0.30,                  // ≥30 % non-printable → looks binary
  HISTOGRAM_TOP_N       : 5,
});

const WIN = Object.freeze({
  INFINITE                 : 0xFFFFFFFF,
  WAIT_OBJECT_0            : 0x00000000,
  WAIT_TIMEOUT             : 0x00000102,
  MEM_COMMIT               : 0x1000,
  MEM_RESERVE              : 0x2000,
  PAGE_READWRITE           : 0x04,
  PAGE_EXECUTE_READ        : 0x20,
  PAGE_EXECUTE_READWRITE   : 0x40,
});


// ═══════════════════════════════════════════════════════════════════════════
//  Terminal output
// ═══════════════════════════════════════════════════════════════════════════

const log = {
  info    : (msg) => console.log(`[i] ${msg}`),
  step    : (msg) => console.log(`[+] ${msg}`),
  warn    : (msg) => console.warn(`[!] ${msg}`),
  error   : (msg) => console.error(`[✗] ${msg}`),
  success : (msg) => console.log(`[✓] ${msg}`),
  detail  : (msg) => console.log(`      ${msg}`),
};

function fail(message) {
  log.error(message);
  process.exit(1);
}


// ═══════════════════════════════════════════════════════════════════════════
//  Help text
// ═══════════════════════════════════════════════════════════════════════════

function buildHelpText() {
  const prog = path.basename(process.argv[1]);
  return `
Usage: node ${prog} <file> [options]

Options:
  --xor-key, -k <0-255>     XOR-decode shellcode with a single-byte key
  --wait, -w <ms>           WaitForSingleObject timeout (default: infinite; 0 = non-blocking)
  --max-size, -m <bytes>    Maximum input file size (default: ${CONFIG.DEFAULT_MAX_FILE_SIZE})
  --format, -f <fmt>        Force input format: auto | raw | hex  (default: auto)
  --analyze-only, -a        Static analysis only — never execute
  --help, -h                Show this help

Format detection:
  • Raw binary       — extensions: ${CONFIG.RAW_EXTENSIONS.join(', ')}
  • Hex text (\\xNN)  — extensions: ${CONFIG.HEX_EXTENSIONS.join(', ')}
  • Unknown ext      — content is probed; use --format to override.

Safety:
  Analysis (SHA-256, entropy, byte histogram) always runs before execution.
  Use --analyze-only to inspect a sample without running it.
`;
}


// ═══════════════════════════════════════════════════════════════════════════
//  CLI argument parsing
// ═══════════════════════════════════════════════════════════════════════════

function parseInteger(raw, flag, { min, max } = {}) {
  if (typeof raw !== 'string' || raw.length === 0) {
    throw new Error(`${flag}: value is required`);
  }
  const isHex = /^0[xX]/.test(raw);
  const isDec = /^[0-9]+$/.test(raw);
  if (!isHex && !isDec) {
    throw new Error(`${flag}: expected base-10 or 0x-prefixed integer, got "${raw}"`);
  }

  const n = parseInt(raw, isHex ? 16 : 10);
  if (!Number.isSafeInteger(n)) {
    throw new Error(`${flag}: value out of range, got "${raw}"`);
  }
  if (min !== undefined && n < min) throw new Error(`${flag}: must be >= ${min}, got ${n}`);
  if (max !== undefined && n > max) throw new Error(`${flag}: must be <= ${max}, got ${n}`);
  return n;
}

const FLAG_HANDLERS = {
  '--xor-key': (opts, value) => {
    opts.xorKey = parseInteger(value, '--xor-key', { min: 0, max: 255 });
  },
  '--wait': (opts, value) => {
    opts.waitMs = parseInteger(value, '--wait', { min: 0, max: WIN.INFINITE });
  },
  '--max-size': (opts, value) => {
    opts.maxSize = parseInteger(value, '--max-size', { min: 1 });
  },
  '--format': (opts, value) => {
    const fmt = value.toLowerCase();
    if (!CONFIG.ALLOWED_FORMATS.includes(fmt)) {
      throw new Error(`--format: expected ${CONFIG.ALLOWED_FORMATS.join(' | ')}, got "${value}"`);
    }
    opts.format = fmt;
  },
};

// Alias table for short flags.
const FLAG_ALIASES = {
  '-k': '--xor-key',
  '-w': '--wait',
  '-m': '--max-size',
  '-f': '--format',
  '-h': '--help',
  '-a': '--analyze-only',
};

function parseArguments(argv) {
  const opts = {
    filePath    : null,
    xorKey      : null,
    waitMs      : WIN.INFINITE,
    maxSize     : CONFIG.DEFAULT_MAX_FILE_SIZE,
    format      : 'auto',
    analyzeOnly : false,
    help        : false,
  };
  const positionals = [];

  for (let i = 0; i < argv.length; i++) {
    const rawArg = argv[i];
    const arg    = FLAG_ALIASES[rawArg] || rawArg;

    if (arg === '--help')         { opts.help = true; continue; }
    if (arg === '--analyze-only') { opts.analyzeOnly = true; continue; }

    if (FLAG_HANDLERS[arg]) {
      const value = argv[++i];
      if (value === undefined) throw new Error(`${rawArg} requires a value`);
      FLAG_HANDLERS[arg](opts, value);
      continue;
    }

    if (arg.startsWith('-')) throw new Error(`unknown option: ${rawArg}`);
    positionals.push(rawArg);
  }

  if (opts.help) return opts;

  if (positionals.length === 0) throw new Error('missing <file> argument');
  if (positionals.length > 1)   throw new Error(`expected exactly one <file>, got ${positionals.length}`);

  opts.filePath = positionals[0];
  return opts;
}


// ═══════════════════════════════════════════════════════════════════════════
//  File loading
// ═══════════════════════════════════════════════════════════════════════════

async function loadFile(originalPath, maxSize) {
  const resolvedPath = path.resolve(originalPath);

  let stat;
  try {
    stat = await fs.stat(resolvedPath);
  } catch (err) {
    fail(`cannot stat "${originalPath}": ${err.message}`);
  }

  if (!stat.isFile())          fail(`not a regular file: ${originalPath}`);
  if (stat.size === 0)         fail(`file is empty: ${originalPath}`);
  if (stat.size > maxSize)     fail(`file is ${stat.size} bytes, exceeds limit of ${maxSize} (see --max-size)`);

  try {
    const buffer = await fs.readFile(resolvedPath);
    return { buffer, resolvedPath };
  } catch (err) {
    fail(`cannot read "${originalPath}": ${err.message}`);
  }
}


// ═══════════════════════════════════════════════════════════════════════════
//  Format detection & parsing
// ═══════════════════════════════════════════════════════════════════════════

function extensionOf(filePath) {
  return path.extname(filePath).toLowerCase();
}

function hasHexEscapes(text) {
  return /\\x[0-9a-f]{2}/i.test(text);
}

function looksLikeBinary(buffer) {
  if (buffer.length === 0) return false;
  let nonPrintable = 0;
  for (const byte of buffer) {
    const isPrintable = (byte >= 0x20 && byte <= 0x7e) || byte === 0x09 || byte === 0x0a || byte === 0x0d;
    if (!isPrintable) nonPrintable++;
  }
  return nonPrintable / buffer.length > CONFIG.PROBE_PRINTABLE_RATIO;
}

function parseHexText(text) {
  const matches = [...text.matchAll(/\\x([0-9a-f]{2})/gi)];
  if (matches.length === 0) throw new Error('no \\xNN patterns found');
  return Buffer.from(matches.map(m => parseInt(m[1], 16)));
}

function detectFormat(resolvedPath, rawBuffer, forcedFormat) {
  const ext = extensionOf(resolvedPath);

  if (forcedFormat === 'raw') return { kind: 'raw', source: 'forced' };
  if (forcedFormat === 'hex') return { kind: 'hex', source: 'forced' };

  // forcedFormat === 'auto'
  if (CONFIG.RAW_EXTENSIONS.includes(ext)) return { kind: 'raw', source: 'extension' };
  if (CONFIG.HEX_EXTENSIONS.includes(ext)) return { kind: 'hex', source: 'extension' };

  const text = rawBuffer.toString('utf8');
  if (hasHexEscapes(text))   return { kind: 'hex', source: 'probed' };
  if (looksLikeBinary(rawBuffer)) return { kind: 'raw', source: 'probed' };

  throw new Error(
    `cannot determine format for "${path.basename(resolvedPath)}"; use --format raw|hex to override`
  );
}

function decodeShellcode(rawBuffer, resolvedPath, forcedFormat) {
  const { kind, source } = detectFormat(resolvedPath, rawBuffer, forcedFormat);

  const shellcode = kind === 'raw'
    ? Buffer.from(rawBuffer)
    : parseHexText(rawBuffer.toString('utf8'));

  if (shellcode.length === 0) throw new Error('decoded shellcode is empty');
  return { shellcode, formatLabel: `${kind} (${source})` };
}

function applyXor(buffer, key) {
  const copy = Buffer.from(buffer);
  for (let i = 0; i < copy.length; i++) copy[i] ^= key;
  return copy;
}


// ═══════════════════════════════════════════════════════════════════════════
//  Static analysis
// ═══════════════════════════════════════════════════════════════════════════

function computeEntropy(buffer) {
  if (buffer.length === 0) return 0;
  const counts = new Uint32Array(256);
  for (const byte of buffer) counts[byte]++;

  let entropy = 0;
  for (const count of counts) {
    if (count === 0) continue;
    const p = count / buffer.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function describeEntropy(entropy) {
  if (entropy < 4.0) return 'low (plaintext-like)';
  if (entropy < 6.0) return 'moderate';
  if (entropy < 7.5) return 'high (compressed/encrypted)';
  return 'very high (encrypted/compressed)';
}

function topByteFrequencies(buffer, topN) {
  const counts = new Uint32Array(256);
  for (const byte of buffer) counts[byte]++;

  return Array.from(counts)
    .map((count, byte) => ({ byte, count }))
    .filter(({ count }) => count > 0)
    .sort((a, b) => b.count - a.count)
    .slice(0, topN)
    .map(({ byte, count }) => {
      const pct = ((count / buffer.length) * 100).toFixed(1);
      return `0x${byte.toString(16).padStart(2, '0')} × ${count} (${pct}%)`;
    })
    .join(', ');
}

function reportAnalysis(buffer, label) {
  const sha256  = crypto.createHash('sha256').update(buffer).digest('hex');
  const entropy = computeEntropy(buffer);
  const top     = topByteFrequencies(buffer, CONFIG.HISTOGRAM_TOP_N);

  log.step(`static analysis — ${label}`);
  log.detail(`SHA-256    : ${sha256}`);
  log.detail(`Size       : ${buffer.length} bytes`);
  log.detail(`Entropy    : ${entropy.toFixed(3)} / 8.000  (${describeEntropy(entropy)})`);
  log.detail(`Top bytes  : ${top || '(empty)'}`);
}


// ═══════════════════════════════════════════════════════════════════════════
//  Windows execution (isolated in its own module-level function)
// ═══════════════════════════════════════════════════════════════════════════

function loadKernel32() {
  const k32 = koffi.load('kernel32.dll');
  return {
    VirtualAlloc        : k32.func('void * __stdcall VirtualAlloc(void * lpAddress, size_t dwSize, uint32_t flAllocationType, uint32_t flProtect)'),
    VirtualProtect      : k32.func('bool __stdcall VirtualProtect(void * lpAddress, size_t dwSize, uint32_t flNewProtect, uint32_t * lpflOldProtect)'),
    RtlCopyMemory       : k32.func('void __stdcall RtlCopyMemory(void * Destination, const void * Source, size_t Length)'),
    CreateThread        : k32.func('void * __stdcall CreateThread(void * lpThreadAttributes, size_t dwStackSize, void * lpStartAddress, void * lpParameter, uint32_t dwCreationFlags, uint32_t * lpThreadId)'),
    WaitForSingleObject : k32.func('uint32_t __stdcall WaitForSingleObject(void * hHandle, uint32_t dwMilliseconds)'),
    GetExitCodeThread   : k32.func('bool __stdcall GetExitCodeThread(void * hThread, uint32_t * lpExitCode)'),
    CloseHandle         : k32.func('bool __stdcall CloseHandle(void * hObject)'),
  };
}

function lastError() {
  try {
    return koffi.win32?.GetLastError?.() ?? 'unknown';
  } catch {
    return 'unknown';
  }
}

function allocateExecutablePage(api, shellcode) {
  // 1. Allocate RW memory.
  const addr = api.VirtualAlloc(null, shellcode.length, WIN.MEM_COMMIT | WIN.MEM_RESERVE, WIN.PAGE_READWRITE);
  if (!addr) fail(`VirtualAlloc(${shellcode.length} bytes) failed (GetLastError: ${lastError()})`);
  log.step(`allocated RW memory @ 0x${addr.toString(16)}`);

  // 2. Copy shellcode into it.
  api.RtlCopyMemory(addr, shellcode, shellcode.length);
  log.step('shellcode copied into target page');

  // 3. Try RX first; fall back to RWX.
  const oldProtect = Buffer.alloc(4);
  if (api.VirtualProtect(addr, shellcode.length, WIN.PAGE_EXECUTE_READ, oldProtect)) {
    const prev = oldProtect.readUInt32LE(0).toString(16).padStart(8, '0');
    log.step(`page marked RX (previous protection: 0x${prev})`);
    return addr;
  }

  log.warn(`RX protection failed (GetLastError: ${lastError()}); trying RWX`);
  if (!api.VirtualProtect(addr, shellcode.length, WIN.PAGE_EXECUTE_READWRITE, oldProtect)) {
    fail(`VirtualProtect(RWX) failed (GetLastError: ${lastError()})`);
  }
  log.step('page marked RWX');
  return addr;
}

function startAndWaitForThread(api, addr, waitMs) {
  const threadIdBuffer = Buffer.alloc(4);
  const thread = api.CreateThread(null, 0, addr, null, 0, threadIdBuffer);
  if (!thread) fail(`CreateThread failed (GetLastError: ${lastError()})`);

  const threadId = threadIdBuffer.readUInt32LE(0);
  log.step(`thread started (TID: ${threadId})`);

  if (waitMs === 0) {
    log.info('non-blocking mode — exiting immediately');
    process.exit(0);
  }

  const waitLabel = waitMs === WIN.INFINITE ? '∞' : `${waitMs} ms`;
  log.step(`waiting for thread (timeout: ${waitLabel}) ...`);

  const result = api.WaitForSingleObject(thread, waitMs);

  if (result === WIN.WAIT_OBJECT_0) {
    const exitCodeBuffer = Buffer.alloc(4);
    if (api.GetExitCodeThread(thread, exitCodeBuffer)) {
      const code = exitCodeBuffer.readUInt32LE(0).toString(16).padStart(8, '0');
      log.success(`thread completed (exit code: 0x${code})`);
    } else {
      log.success('thread completed');
    }
  } else if (result === WIN.WAIT_TIMEOUT) {
    log.warn('timeout reached — thread still running');
  } else {
    log.warn(`WaitForSingleObject returned 0x${result.toString(16)}`);
  }

  api.CloseHandle(thread);
}

function executeShellcode(shellcode, waitMs) {
  if (process.platform !== 'win32') {
    fail('execution requires Windows; use --analyze-only on other platforms');
  }

  log.warn('this will execute the shellcode in the current process');

  const api = loadKernel32();
  const addr = allocateExecutablePage(api, shellcode);

  // Defense-in-depth: wipe the JS-side copy now that it lives in executable memory.
  shellcode.fill(0);

  startAndWaitForThread(api, addr, waitMs);
}


// ═══════════════════════════════════════════════════════════════════════════
//  Main flow
// ═══════════════════════════════════════════════════════════════════════════

async function main() {
  let opts;
  try {
    opts = parseArguments(process.argv.slice(2));
  } catch (err) {
    fail(`${err.message} (use --help)`);
  }

  if (opts.help) {
    console.log(buildHelpText());
    process.exit(0);
  }

  log.info(`loading: ${opts.filePath}`);
  const { buffer: rawBuffer, resolvedPath } = await loadFile(opts.filePath, opts.maxSize);

  let shellcode, formatLabel;
  try {
    ({ shellcode, formatLabel } = decodeShellcode(rawBuffer, resolvedPath, opts.format));
  } catch (err) {
    fail(`parse failed (requested format: ${opts.format}): ${err.message}`);
  }

  log.step(`format   : ${formatLabel} — ${shellcode.length} bytes`);
  reportAnalysis(shellcode, 'raw');

  if (opts.xorKey !== null) {
    log.step(`applying XOR key 0x${opts.xorKey.toString(16).padStart(2, '0')}`);
    shellcode = applyXor(shellcode, opts.xorKey);
    reportAnalysis(shellcode, 'decoded');
  }

  if (opts.analyzeOnly) {
    log.info('--analyze-only: skipping execution');
    return;
  }

  executeShellcode(shellcode, opts.waitMs);
}

main().catch((err) => {
  log.error(err.message);
  process.exit(1);
});
