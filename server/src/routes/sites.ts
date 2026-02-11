import { Router, type Request, type Response } from 'express';
import { registerSite, getSiteByApiKey } from '../services/sites';
import type { AgentAuthConfig, SiteRegistrationRequest } from '../types';

export function sitesRouter(_config: AgentAuthConfig): Router {
  const router = Router();

  // POST /api/sites/register - Register a new site
  router.post('/register', (req: Request, res: Response) => {
    const { domain, callbackUrls, minScore } = req.body as SiteRegistrationRequest;

    if (!domain) {
      res.status(400).json({ error: 'domain is required' });
      return;
    }

    if (!callbackUrls || !Array.isArray(callbackUrls) || callbackUrls.length === 0) {
      res.status(400).json({ error: 'callbackUrls must be a non-empty array' });
      return;
    }

    if (minScore === undefined || typeof minScore !== 'number' || minScore < 0 || minScore > 100) {
      res.status(400).json({ error: 'minScore must be a number between 0 and 100' });
      return;
    }

    const site = registerSite({ domain, callbackUrls, minScore });

    res.status(201).json({
      siteId: site.siteId,
      apiKey: site.apiKey,
      domain: site.domain,
      callbackUrls: site.callbackUrls,
      minScore: site.minScore,
      createdAt: site.createdAt,
      message: 'Save your API key - it cannot be retrieved later.',
    });
  });

  // GET /api/sites/me - Get site info for the current API key
  router.get('/me', (req: Request, res: Response) => {
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

    res.json({
      siteId: site.siteId,
      domain: site.domain,
      callbackUrls: site.callbackUrls,
      minScore: site.minScore,
      createdAt: site.createdAt,
    });
  });

  return router;
}
