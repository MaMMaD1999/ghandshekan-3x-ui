import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';

// Keep the same operation ID after a lost response, including a page reload.
// Store only a digest and a random ID: never persist client credentials/body.
const pending = new Map<string, string>();

export async function lifecycleRequest<T extends { success: boolean }>(
  scope: string,
  body: unknown,
  send: (id: string) => Promise<T>,
): Promise<T> {
  const context = typeof location === 'undefined' ? '' : location.origin + location.pathname;
  const storageKey =
    'mesh-operation/' + bytesToHex(sha256(utf8ToBytes(JSON.stringify([context, scope, body]))));
  let id = pending.get(storageKey);
  try {
    id ??= sessionStorage.getItem(storageKey) ?? undefined;
  } catch {
    /* memory fallback */
  }
  id ??= Array.from(crypto.getRandomValues(new Uint8Array(24)), (byte) =>
    byte.toString(16).padStart(2, '0'),
  ).join('');
  pending.set(storageKey, id);
  try {
    sessionStorage.setItem(storageKey, id);
  } catch {
    /* memory fallback */
  }
  const result = await send(id);
  if (result.success) {
    pending.delete(storageKey);
    try {
      sessionStorage.removeItem(storageKey);
    } catch {
      /* memory fallback */
    }
  }
  return result;
}
