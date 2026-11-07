import { describe, expect, it } from 'vitest';
import { lifecycleRequest } from '../utils/lifecycleRequest';

describe('administrative lifecycle retry', () => {
  it('reuses the ID after a lost response, then permits a new deliberate reset', async () => {
    let first = '';
    await expect(
      lifecycleRequest('reset/test-lost', undefined, async (id) => {
        first = id;
        throw new Error('response lost after commit');
      }),
    ).rejects.toThrow();
    await lifecycleRequest('reset/test-lost', undefined, async (id) => {
      expect(id).toBe(first);
      return { success: true };
    });
    await lifecycleRequest('reset/test-lost', undefined, async (id) => {
      expect(id).not.toBe(first);
      return { success: true };
    });
  });
  it('retains an unsuccessful operation but separates edited input', async () => {
    let first = '';
    await lifecycleRequest('renew/test-error', { limit: 10 }, async (id) => {
      first = id;
      return { success: false };
    });
    await lifecycleRequest('renew/test-error', { limit: 10 }, async (id) => {
      expect(id).toBe(first);
      return { success: false };
    });
    await lifecycleRequest('renew/test-error', { limit: 20 }, async (id) => {
      expect(id).not.toBe(first);
      return { success: true };
    });
  });
});
