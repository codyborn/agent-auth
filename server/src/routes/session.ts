import { Router, type Request, type Response } from 'express';
import { verifyToken } from '../services/jwt';
import type { AgentAuthConfig } from '../types';

export function sessionRouter(config: AgentAuthConfig): Router {
  const router = Router();

  // GET /api/session - Validate a JWT and return session info
  router.get('/', (req: Request, res: Response) => {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      res.status(401).json({ error: 'Missing or invalid Authorization header' });
      return;
    }

    const token = authHeader.slice(7);
    const payload = verifyToken(token, config.jwtSecret);

    if (!payload) {
      res.status(401).json({ error: 'Invalid or expired token' });
      return;
    }

    res.json({
      valid: true,
      address: payload.address,
      siteId: payload.siteId,
      sybilScore: payload.sybilScore,
      sybilBreakdown: payload.sybilBreakdown,
      expiresAt: payload.exp,
    });
  });

  return router;
}
