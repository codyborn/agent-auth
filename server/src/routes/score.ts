import { Router, type Request, type Response } from 'express';
import { isAddress } from 'viem';
import { computeSybilScore } from '../services/sybil';
import { getDonationBoost } from '../services/boost';
import type { AgentAuthConfig } from '../types';

export function scoreRouter(config: AgentAuthConfig): Router {
  const router = Router();

  // GET /api/score/:address - Get sybil score for an address (no auth required)
  // Score is always aggregated across all supported chains
  router.get('/:address', async (req: Request, res: Response) => {
    const { address } = req.params;

    if (!isAddress(address)) {
      res.status(400).json({ error: 'Invalid Ethereum address' });
      return;
    }

    try {
      const result = await computeSybilScore(address, config.rpcUrls);

      // Apply donation boost
      const donationBoost = getDonationBoost(address);
      if (donationBoost > 0) {
        result.breakdown.donationBoost = donationBoost;
        result.breakdown.totalScore = Math.min(100, result.breakdown.totalScore + donationBoost);
      }

      res.json({
        address,
        sybilScore: result.breakdown.totalScore,
        sybilBreakdown: result.breakdown,
        details: result.details,
      });
    } catch (err: any) {
      console.error('Sybil score error:', err);
      res.status(500).json({ error: 'Failed to compute sybil score', message: err.message });
    }
  });

  return router;
}
