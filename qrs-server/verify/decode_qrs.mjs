#!/usr/bin/env node
/**
 * Decodes the text content of a `.qrs` file into its signed objects
 * (a single object or a bundle). The Python server delegates protocol decoding
 * here so it never re-implements qrs-core logic.
 *
 * Input (stdin, JSON): `{"qrs": "<file text>"}`  (legacy argv: `<file text>`)
 * Output: `{ ok, kind: 'object'|'bundle', objects: [{type, bytesB64}], error? }`
 */
import { decodeQrsFile } from 'qrs-core';

function readStdin() {
  return new Promise((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => (data += chunk));
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', reject);
  });
}

async function readText() {
  const args = process.argv.slice(2);
  if (args.length >= 1) return args[0];
  const raw = await readStdin();
  try {
    const parsed = JSON.parse(raw);
    return parsed.qrs ?? raw;
  } catch {
    return raw;
  }
}

const text = await readText();
try {
  if (!text) throw new Error('missing .qrs text');
  const decoded = decodeQrsFile(text);
  if (!decoded) throw new Error('not a valid .qrs payload');
  const objects = decoded.kind === 'object'
    ? [{ type: decoded.payload.type, bytesB64: decoded.payload.bytesB64 }]
    : decoded.objects;
  console.log(JSON.stringify({ ok: true, kind: decoded.kind, objects, error: undefined }));
} catch (error) {
  console.log(JSON.stringify({ ok: false, error: error instanceof Error ? error.message : String(error) }));
}
