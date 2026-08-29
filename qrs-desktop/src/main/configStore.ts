/**
 * Global app configuration store (main process).
 *
 * A tiny JSON-file-backed store for app-level settings (language, calendar,
 * SDoc table columns, …). This is NOT part of the protocol — it is purely local
 * UI/UX configuration shared across windows and persisted across restarts.
 */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import type { GlobalConfig } from '../shared/types.js';

export class GlobalConfigStore {
  private readonly file: string;
  private cache: GlobalConfig;

  constructor(dataDir: string) {
    this.file = join(dataDir, 'config.json');
    this.cache = this.load();
  }

  private load(): GlobalConfig {
    try {
      const raw = JSON.parse(readFileSync(this.file, 'utf8'));
      return typeof raw === 'object' && raw !== null && !Array.isArray(raw) ? (raw as GlobalConfig) : {};
    } catch {
      return {};
    }
  }

  private persist(): void {
    mkdirSync(join(this.file, '..'), { recursive: true });
    writeFileSync(this.file, JSON.stringify(this.cache, null, 2));
  }

  get(): GlobalConfig {
    return { ...this.cache };
  }

  set(config: GlobalConfig): GlobalConfig {
    this.cache = { ...config };
    this.persist();
    return this.get();
  }
}