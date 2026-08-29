import { beforeEach, describe, expect, it, vi } from 'vitest';

const storage = new Map<string, string>();

vi.mock('@react-native-async-storage/async-storage', () => ({
  default: {
    getItem: async (key: string) => storage.get(key) ?? null,
    setItem: async (key: string, value: string) => void storage.set(key, value),
    removeItem: async (key: string) => void storage.delete(key),
  },
}));

import { clearAdminPassword, setAdminPassword, verifyAdminPassword } from '../lib/password';

describe('admin password verification', () => {
  beforeEach(async () => {
    storage.clear();
    await clearAdminPassword();
    await setAdminPassword('correct');
  });

  it('requires a fresh check when changing the password', async () => {
    expect(await verifyAdminPassword('correct')).toBe(true);

    // A normal trust action can reuse the recent authentication window.
    expect(await verifyAdminPassword('wrong')).toBe(true);
    // Password changes must not reuse that window.
    expect(await verifyAdminPassword('wrong', { requireFresh: true })).toBe(false);
    expect(await verifyAdminPassword('correct', { requireFresh: true })).toBe(true);
  });
});
