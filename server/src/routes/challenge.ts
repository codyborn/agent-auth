import { Router, type Request, type Response } from 'express';
import { createChallenge } from '../services/challenge';
import { getSiteByApiKey } from '../services/sites';
import type { AgentAuthConfig, ChallengeRequest } from '../types';

export function challengeRouter(config: AgentAuthConfig): Router {
  const router = Router();

  // POST /api/challenge - Request a new auth challenge
  // Requires x-api-key header from a registered site
  router.post('/', (req: Request, res: Response) => {
    const apiKey = req.headers['x-api-key'] as string;
    if (!apiKey) {
      res.status(401).json({ error: 'x-api-key header is required. Register your site at POST /api/sites/register first.' });
      return;
    }

    const site = getSiteByApiKey(apiKey);
    if (!site) {
      res.status(401).json({ error: 'Invalid API key' });
      return;
    }

    const { address } = req.body as ChallengeRequest;

    const challenge = createChallenge(
      site.siteId,
      site.domain,
      `https://${site.domain}`,
      address,
      config.challengeTTL
    );

    res.json({
      challenge: challenge.message,
      nonce: challenge.nonce,
      issuedAt: challenge.issuedAt,
      expirationTime: challenge.expirationTime,
    });
  });

  return router;
}
