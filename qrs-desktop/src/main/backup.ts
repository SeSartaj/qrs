import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const FILE_NAME = 'qrs-backup.json';
function encrypt(value: unknown, password: string): string {
  if (password.length < 8) throw new Error('Backup password must contain at least 8 characters.');
  const salt = randomBytes(16); const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', scryptSync(password, salt, 32), iv);
  const data = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
  return JSON.stringify({ type: 'qrs-backup', version: 1, salt: salt.toString('base64'), iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), data: data.toString('base64') });
}
function decrypt(raw: string, password: string): Record<string, string> {
  if (password.length < 8) throw new Error('Backup password must contain at least 8 characters.');
  let envelope: { type?: string; version?: number; salt: string; iv: string; tag: string; data: string };
  try { envelope = JSON.parse(raw); } catch { throw new Error('Invalid backup file.'); }
  if (envelope.type !== 'qrs-backup' || envelope.version !== 1) throw new Error('Unsupported backup format.');
  try {
    const decipher = createDecipheriv('aes-256-gcm', scryptSync(password, Buffer.from(envelope.salt, 'base64'), 32), Buffer.from(envelope.iv, 'base64'));
    decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
    const value = JSON.parse(Buffer.concat([decipher.update(Buffer.from(envelope.data, 'base64')), decipher.final()]).toString('utf8'));
    if (!value || value.type !== 'qrs-data' || typeof value.files !== 'object') throw new Error();
    const files = value.files as Record<string, string>;
    if (Object.keys(files).some((name) => !/^[a-zA-Z0-9._-]+$/.test(name))) throw new Error();
    return files;
  } catch { throw new Error('Incorrect backup password or corrupted backup.'); }
}
export function makeBackup(dataDir: string, password: string): string {
  const files: Record<string, string> = {};
  if (existsSync(dataDir)) for (const name of readdirSync(dataDir)) {
    if (name === 'backups') continue;
    try { files[name] = readFileSync(join(dataDir, name), 'utf8'); } catch { /* skip non-text entries */ }
  }
  return encrypt({ type: 'qrs-data', files }, password);
}
export function restoreBackup(dataDir: string, raw: string, password: string): void {
  const files = decrypt(raw, password);
  const backupDir = join(dataDir, 'backups', `before-restore-${Date.now()}`);
  mkdirSync(backupDir, { recursive: true });
  if (existsSync(dataDir)) for (const name of readdirSync(dataDir)) {
    if (name === 'backups') continue;
    try { writeFileSync(join(backupDir, name), readFileSync(join(dataDir, name))); } catch { /* skip */ }
  }
  mkdirSync(dataDir, { recursive: true });
  for (const [name, contents] of Object.entries(files)) writeFileSync(join(dataDir, name), contents, 'utf8');
}
export { FILE_NAME };
