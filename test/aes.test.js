import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';

function decodeAesKey(aesKey) {
  const base64 = aesKey.endsWith('=') ? aesKey : `${aesKey}=`;
  return Buffer.from(base64, 'base64');
}

function pkcs7Unpad(buf) {
  const pad = buf[buf.length - 1];
  if (pad < 1 || pad > 32) return buf;
  return buf.subarray(0, buf.length - pad);
}

function decryptWecom({ aesKey, cipherTextBase64 }) {
  const key = decodeAesKey(aesKey);
  const iv = key.subarray(0, 16);
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  decipher.setAutoPadding(false);
  const plain = Buffer.concat([
    decipher.update(Buffer.from(cipherTextBase64, 'base64')),
    decipher.final(),
  ]);
  const unpadded = pkcs7Unpad(plain);

  const msgLen = unpadded.readUInt32BE(16);
  const msgStart = 20;
  const msgEnd = msgStart + msgLen;
  const msg = unpadded.subarray(msgStart, msgEnd).toString('utf8');
  const corpId = unpadded.subarray(msgEnd).toString('utf8');
  return { msg, corpId };
}

describe('wecom aes', () => {
  it('decodeAesKey returns 32 bytes key for 43-char base64 (no =) ', () => {
    // 32 zero bytes -> base64 without trailing '=' is 43 chars
    const b64 = Buffer.alloc(32).toString('base64');
    const noEq = b64.replace(/=+$/, '');
    expect(noEq.endsWith('=')).toBe(false);
    const key = decodeAesKey(noEq);
    expect(key.length).toBe(32);
  });

  it('decryptWecom can decrypt a crafted payload roundtrip', () => {
    // This is a synthetic roundtrip to lock the structure: random16 + msgLen + msg + corpId + padding.
    const key = crypto.randomBytes(32);
    const iv = key.subarray(0,16);
    const aesKey = key.toString('base64').replace(/=+$/, '');

    const random16 = crypto.randomBytes(16);
    const msg = Buffer.from('<xml><Test>hi</Test></xml>', 'utf8');
    const corpId = Buffer.from('corp123', 'utf8');
    const len = Buffer.alloc(4);
    len.writeUInt32BE(msg.length, 0);
    let raw = Buffer.concat([random16, len, msg, corpId]);

    // pkcs7 pad to 32
    const block = 32;
    const pad = block - (raw.length % block || block);
    raw = Buffer.concat([raw, Buffer.alloc(pad, pad)]);

    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    cipher.setAutoPadding(false);
    const enc = Buffer.concat([cipher.update(raw), cipher.final()]).toString('base64');

    const out = decryptWecom({ aesKey, cipherTextBase64: enc });
    expect(out.msg).toBe(msg.toString('utf8'));
    expect(out.corpId).toBe(corpId.toString('utf8'));
  });
});
