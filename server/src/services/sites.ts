import { randomBytes } from 'crypto';
import type { RegisteredSite, SiteRegistrationRequest } from '../types';

// In-memory store (use a database in production)
const sites = new Map<string, RegisteredSite>();

// Index by API key for fast lookup
const sitesByApiKey = new Map<string, RegisteredSite>();

function generateId(): string {
  return 'site_' + randomBytes(12).toString('hex');
}

function generateApiKey(): string {
  return 'aa_' + randomBytes(24).toString('hex');
}

export function registerSite(req: SiteRegistrationRequest): RegisteredSite {
  const siteId = generateId();
  const apiKey = generateApiKey();

  const site: RegisteredSite = {
    siteId,
    apiKey,
    domain: req.domain,
    callbackUrls: req.callbackUrls,
    minScore: Math.max(0, Math.min(100, req.minScore)),
    createdAt: new Date().toISOString(),
  };

  sites.set(siteId, site);
  sitesByApiKey.set(apiKey, site);
  return site;
}

export function getSiteByApiKey(apiKey: string): RegisteredSite | null {
  return sitesByApiKey.get(apiKey) || null;
}

export function getSiteById(siteId: string): RegisteredSite | null {
  return sites.get(siteId) || null;
}

export function updateSite(
  siteId: string,
  updates: Partial<Pick<RegisteredSite, 'callbackUrls' | 'minScore'>>
): RegisteredSite | null {
  const site = sites.get(siteId);
  if (!site) return null;

  if (updates.callbackUrls !== undefined) site.callbackUrls = updates.callbackUrls;
  if (updates.minScore !== undefined) site.minScore = Math.max(0, Math.min(100, updates.minScore));

  return site;
}
