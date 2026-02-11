import { Router, type Request, type Response } from 'express';
import { verifyMessage } from 'viem';
import { validateChallenge } from '../services/challenge';
import { getSiteByApiKey } from '../services/sites';
import { computeSybilScore } from '../services/sybil';
import { getCachedAttestation, createAttestation } from '../services/attestation';
import { createToken } from '../services/jwt';
import type { AgentAuthConfig, VerifyRequest } from '../types';

// Parse SIWE-style message to extract fields
function parseMessage(message: string): {
  domain: string;
  address: string;
  uri: string;
  nonce: string;
  issuedAt: string;
  expirationTime: string;
} | null {
  try {
    const lines = message.split('\n');
    const address = lines[1]?.trim();
    const uri = lines.find((l) => l.startsWith('URI:'))?.replace('URI: ', '').trim();
    const nonce = lines.find((l) => l.startsWith('Nonce:'))?.replace('Nonce: ', '').trim();
    const issuedAt = lines
      .find((l) => l.startsWith('Issued At:'))
      ?.replace('Issued At: ', '')
      .trim();
    const expirationTime = lines
      .find((l) => l.startsWith('Expiration Time:'))
      ?.replace('Expiration Time: ', '')
      .trim();
    const domain = lines[0]?.replace(' wants you to sign in with your Ethereum account:', '').trim();

    if (!address || !nonce || !domain) return null;

    return {
      domain: domain!,
      address: address!,
      uri: uri || '',
      nonce: nonce!,
      issuedAt: issuedAt || '',
      expirationTime: expirationTime || '',
    };
  } catch {
    return null;
  }
}

export function verifyRouter(config: AgentAuthConfig): Router {
  const router = Router();

  router.post('/', async (req: Request, res: Response) => {
    const apiKey = req.headers['x-api-key'] as string;
    if (!apiKey) {
      res.status(401).json({ error: 'x-api-key header is required' });
      return;
    }

    const site = getSiteByApiKey(apiKey);
    if (!site) {
      res.status(401).json({ error: 'Invalid API key' });
      return;
    }

    const { message, signature } = req.body as VerifyRequest;

    if (!message || !signature) {
      res.status(400).json({ error: 'message and signature are required' });
      return;
    }

    const parsed = parseMessage(message);
    if (!parsed) {
      res.status(400).json({ error: 'Invalid message format' });
      return;
    }

    const challenge = validateChallenge(parsed.nonce);
    if (!challenge) {
      res.status(401).json({ error: 'Invalid or expired challenge nonce' });
      return;
    }

    if (challenge.siteId !== site.siteId) {
      res.status(401).json({ error: 'Challenge does not belong to this site' });
      return;
    }

    if (new Date(parsed.expirationTime) < new Date()) {
      res.status(401).json({ error: 'Challenge has expired' });
      return;
    }

    // Verify the wallet signature
    let isValid: boolean;
    try {
      isValid = await verifyMessage({
        address: parsed.address as `0x${string}`,
        message,
        signature: signature as `0x${string}`,
      });
    } catch (err) {
      res.status(401).json({ error: 'Signature verification failed' });
      return;
    }

    if (!isValid) {
      res.status(401).json({ error: 'Invalid signature' });
      return;
    }

    // Check for existing cached attestation (skip expensive RPC if fresh)
    let sybilResult;
    let attestation;
    const cached = getCachedAttestation(parsed.address);

    if (cached) {
      // Use cached score - no RPC calls needed
      sybilResult = {
        breakdown: {
          balanceScore: cached.balanceScore,
          txCountScore: cached.txCountScore,
          accountAgeScore: cached.accountAgeScore,
          totalScore: cached.score,
        },
        details: null, // Details not available from cache
      };
      attestation = cached;
    } else {
      // Compute fresh score across all chains
      try {
        sybilResult = await computeSybilScore(parsed.address, config.rpcUrls);
      } catch (err) {
        console.error('Sybil check error:', err);
        sybilResult = {
          breakdown: {
            balanceScore: 0,
            txCountScore: 0,
            accountAgeScore: 0,
            totalScore: 0,
          },
          details: {
            totalBalanceETH: 0,
            totalTransactionCount: 0,
            chainsChecked: 0,
            chainsWithActivity: 0,
            perChain: [],
          },
        };
      }

      // Create signed EIP-712 attestation (also caches it)
      attestation = await createAttestation(
        parsed.address,
        sybilResult.breakdown,
        config.attestationPrivateKey
      );
    }

    // Enforce site's minScore
    if (sybilResult.breakdown.totalScore < site.minScore) {
      res.status(403).json({
        error: 'Sybil score below site minimum',
        sybilScore: sybilResult.breakdown.totalScore,
        requiredScore: site.minScore,
        sybilBreakdown: sybilResult.breakdown,
      });
      return;
    }

    // Create JWT
    const token = createToken(
      parsed.address,
      site.siteId,
      sybilResult.breakdown.totalScore,
      sybilResult.breakdown,
      config.jwtSecret,
      config.jwtExpiresIn
    );

    const decoded = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());

    res.json({
      success: true,
      address: parsed.address,
      sybilScore: sybilResult.breakdown.totalScore,
      sybilBreakdown: sybilResult.breakdown,
      ...(sybilResult.details ? { sybilDetails: sybilResult.details } : {}),
      token,
      expiresAt: decoded.exp,
      // EIP-712 signed attestation - agent can publish to ERC-8004 Validation Registry
      attestation: {
        subject: attestation.subject,
        score: attestation.score,
        balanceScore: attestation.balanceScore,
        txCountScore: attestation.txCountScore,
        accountAgeScore: attestation.accountAgeScore,
        issuedAt: attestation.issuedAt,
        expiresAt: attestation.expiresAt,
        attester: attestation.attester,
        signature: attestation.signature,
      },
    });
  });

  return router;
}
