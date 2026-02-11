export interface Challenge {
  nonce: string;
  domain: string;
  uri: string;
  issuedAt: string;
  expirationTime: string;
  message: string;
  siteId: string;
}

export interface SybilScoreBreakdown {
  balanceScore: number;      // 0-33 (aggregated across chains)
  txCountScore: number;      // 0-34 (aggregated across chains)
  accountAgeScore: number;   // 0-33 (estimated from aggregate tx count)
  totalScore: number;        // 0-100
}

export interface VerifyResult {
  address: string;
  sybilScore: number;
  sybilBreakdown: SybilScoreBreakdown;
  token: string;
  expiresAt: number;
}

export interface ChallengeRequest {
  address?: string;
}

export interface VerifyRequest {
  message: string;
  signature: string;
}

// Site registration
export interface RegisteredSite {
  siteId: string;
  apiKey: string;
  domain: string;
  callbackUrls: string[];
  minScore: number;
  createdAt: string;
}

export interface SiteRegistrationRequest {
  domain: string;
  callbackUrls: string[];
  minScore: number;
}

export interface AgentAuthConfig {
  jwtSecret: string;
  jwtExpiresIn: string;
  challengeTTL: number; // seconds
  rpcUrls: Record<number, string>;
  attestationPrivateKey: string; // Server wallet key for signing EIP-712 attestations
}
