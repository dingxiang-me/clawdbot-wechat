import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';

function sha1(text) {
  return crypto.createHash('sha1').update(text).digest('hex');
}

function computeMsgSignature({ token, timestamp, nonce, encrypt }) {
  const arr = [token, timestamp, nonce, encrypt].map(String).sort();
  return sha1(arr.join(''));
}

describe('wecom signature', () => {
  it('computes deterministic sha1 over sorted fields', () => {
    const sig = computeMsgSignature({
      token: 'token',
      timestamp: '1',
      nonce: '2',
      encrypt: 'cipher',
    });
    expect(sig).toBe(sha1('12ciphertoken'));
  });
});
