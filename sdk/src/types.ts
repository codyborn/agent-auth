export interface AgentAuthOptions {
  serverUrl: string;
  apiKey: string;   // Required: site API key from registration
}

export interface AgentAuthSession {
  address: string;
  sybilScore: number;
  sybilBreakdown: {
    balanceScore: number;
    txCountScore: number;
    accountAgeScore: number;
    totalScore: number;
  };
  sybilDetails: {
    totalBalanceETH: number;
    totalTransactionCount: number;
    chainsChecked: number;
    chainsWithActivity: number;
    perChain: Array<{
      chainId: number;
      chainName: string;
      balanceETH: number;
      txCount: number;
    }>;
  };
  token: string;
  expiresAt: number;
}

export interface ChallengeResponse {
  challenge: string;
  nonce: string;
  issuedAt: string;
  expirationTime: string;
}
