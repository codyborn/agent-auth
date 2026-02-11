import { randomBytes } from 'crypto';
import type { Challenge } from '../types';

// In-memory challenge store (use Redis in production)
const challenges = new Map<string, { challenge: Challenge; expiresAt: number }>();

// Clean up expired challenges periodically
setInterval(() => {
  const now = Date.now();
  for (const [key, value] of challenges) {
    if (value.expiresAt < now) {
      challenges.delete(key);
    }
  }
}, 60_000);

export function generateNonce(): string {
  return randomBytes(16).toString('hex');
}

export function createChallenge(
  siteId: string,
  domain: string,
  uri: string,
  address: string | undefined,
  ttlSeconds: number
): Challenge {
  const nonce = generateNonce();
  const issuedAt = new Date().toISOString();
  const expirationTime = new Date(Date.now() + ttlSeconds * 1000).toISOString();

  const addressLine = address ? address : '<agent-wallet-address>';
  const message = [
    `${domain} wants you to sign in with your Ethereum account:`,
    addressLine,
    '',
    'Sign in with AgentAuth - Verified Agent Authentication',
    '',
    `URI: ${uri}`,
    `Version: 1`,
    `Nonce: ${nonce}`,
    `Issued At: ${issuedAt}`,
    `Expiration Time: ${expirationTime}`,
  ].join('\n');

  const challenge: Challenge = {
    nonce,
    domain,
    uri,
    issuedAt,
    expirationTime,
    message,
    siteId,
  };

  challenges.set(nonce, {
    challenge,
    expiresAt: Date.now() + ttlSeconds * 1000,
  });

  return challenge;
}

export function validateChallenge(nonce: string): Challenge | null {
  const entry = challenges.get(nonce);
  if (!entry) return null;
  if (entry.expiresAt < Date.now()) {
    challenges.delete(nonce);
    return null;
  }
  // Single use - delete after retrieval
  challenges.delete(nonce);
  return entry.challenge;
}
