import { privateKeyToAccount } from 'viem/accounts';
import { hashTypedData } from 'viem';
import type { SybilScoreBreakdown } from '../types';

// EIP-712 domain for AgentAuth attestations
const DOMAIN = {
  name: 'AgentAuth',
  version: '1',
  // No chainId - attestation is chain-agnostic (score is multi-chain)
} as const;

const ATTESTATION_TYPES = {
  SybilAttestation: [
    { name: 'subject', type: 'address' },
    { name: 'score', type: 'uint8' },
    { name: 'balanceScore', type: 'uint8' },
    { name: 'txCountScore', type: 'uint8' },
    { name: 'accountAgeScore', type: 'uint8' },
    { name: 'issuedAt', type: 'uint256' },
    { name: 'expiresAt', type: 'uint256' },
  ],
} as const;

export interface SybilAttestation {
  subject: string;
  score: number;
  balanceScore: number;
  txCountScore: number;
  accountAgeScore: number;
  issuedAt: number;       // unix timestamp
  expiresAt: number;      // unix timestamp
  attester: string;       // AgentAuth server's address
  signature: string;      // EIP-712 signature
}

// Cache: address → attestation (with TTL)
const attestationCache = new Map<string, SybilAttestation>();
const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

// Clean up expired attestations
setInterval(() => {
  const now = Date.now();
  for (const [key, att] of attestationCache) {
    if (att.expiresAt * 1000 < now) {
      attestationCache.delete(key);
    }
  }
}, 5 * 60_000);

let serverAccount: ReturnType<typeof privateKeyToAccount> | null = null;

function getServerAccount(privateKey: string) {
  if (!serverAccount) {
    serverAccount = privateKeyToAccount(privateKey as `0x${string}`);
  }
  return serverAccount;
}

// Check if we have a fresh cached attestation for this address
export function getCachedAttestation(address: string): SybilAttestation | null {
  const cached = attestationCache.get(address.toLowerCase());
  if (!cached) return null;
  if (cached.expiresAt * 1000 < Date.now()) {
    attestationCache.delete(address.toLowerCase());
    return null;
  }
  return cached;
}

// Create and cache a signed EIP-712 attestation
export async function createAttestation(
  address: string,
  breakdown: SybilScoreBreakdown,
  serverPrivateKey: string
): Promise<SybilAttestation> {
  const account = getServerAccount(serverPrivateKey);
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + 24 * 60 * 60; // 24h validity

  const message = {
    subject: address as `0x${string}`,
    score: breakdown.totalScore,
    balanceScore: breakdown.balanceScore,
    txCountScore: breakdown.txCountScore,
    accountAgeScore: breakdown.accountAgeScore,
    issuedAt: BigInt(now),
    expiresAt: BigInt(expiresAt),
  };

  const signature = await account.signTypedData({
    domain: DOMAIN,
    types: ATTESTATION_TYPES,
    primaryType: 'SybilAttestation',
    message,
  });

  const attestation: SybilAttestation = {
    subject: address,
    score: breakdown.totalScore,
    balanceScore: breakdown.balanceScore,
    txCountScore: breakdown.txCountScore,
    accountAgeScore: breakdown.accountAgeScore,
    issuedAt: now,
    expiresAt,
    attester: account.address,
    signature,
  };

  attestationCache.set(address.toLowerCase(), attestation);
  return attestation;
}

// Get the EIP-712 typed data hash (useful for on-chain verification)
export function getAttestationHash(attestation: SybilAttestation): string {
  return hashTypedData({
    domain: DOMAIN,
    types: ATTESTATION_TYPES,
    primaryType: 'SybilAttestation',
    message: {
      subject: attestation.subject as `0x${string}`,
      score: attestation.score,
      balanceScore: attestation.balanceScore,
      txCountScore: attestation.txCountScore,
      accountAgeScore: attestation.accountAgeScore,
      issuedAt: BigInt(attestation.issuedAt),
      expiresAt: BigInt(attestation.expiresAt),
    },
  });
}

// Export domain and types for clients to verify
export const EIP712_DOMAIN = DOMAIN;
export const EIP712_TYPES = ATTESTATION_TYPES;
