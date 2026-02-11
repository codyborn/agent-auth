import jwt from 'jsonwebtoken';
import type { SybilScoreBreakdown } from '../types';

export interface AgentAuthPayload {
  address: string;
  siteId: string;
  sybilScore: number;
  sybilBreakdown: SybilScoreBreakdown;
  iat: number;
  exp: number;
}

export function createToken(
  address: string,
  siteId: string,
  sybilScore: number,
  sybilBreakdown: SybilScoreBreakdown,
  secret: string,
  expiresIn: string
): string {
  return jwt.sign(
    { address, siteId, sybilScore, sybilBreakdown },
    secret,
    { expiresIn }
  );
}

export function verifyToken(token: string, secret: string): AgentAuthPayload | null {
  try {
    return jwt.verify(token, secret) as AgentAuthPayload;
  } catch {
    return null;
  }
}
