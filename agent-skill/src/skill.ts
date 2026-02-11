import { privateKeyToAccount } from 'viem/accounts';

export interface AgentAuthConfig {
  /** AgentAuth server URL (e.g. https://agent-auth-alpha.vercel.app) */
  serverUrl: string;
  /** Site API key from registration */
  apiKey: string;
  /** Agent's Ethereum private key (hex string with 0x prefix) */
  privateKey: `0x${string}`;
}

export interface AuthSession {
  address: string;
  token: string;
  expiresAt: number;
  sybilScore: number;
  sybilBreakdown: {
    balanceScore: number;
    txCountScore: number;
    accountAgeScore: number;
    totalScore: number;
  };
  attestation: {
    subject: string;
    score: number;
    attester: string;
    signature: string;
    issuedAt: number;
    expiresAt: number;
  };
}

export interface ScoreResult {
  address: string;
  sybilScore: number;
  sybilBreakdown: {
    balanceScore: number;
    txCountScore: number;
    accountAgeScore: number;
    totalScore: number;
  };
  details: {
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
}

/**
 * AgentAuth skill for AI agents.
 *
 * Usage:
 *   const agent = new AgentAuthSkill({
 *     serverUrl: 'https://agent-auth-alpha.vercel.app',
 *     apiKey: 'aa_...',
 *     privateKey: '0x...',
 *   });
 *   const session = await agent.authenticate();
 *   const data = await agent.fetch('https://protected-api.com/data');
 */
export class AgentAuthSkill {
  private serverUrl: string;
  private apiKey: string;
  private account: ReturnType<typeof privateKeyToAccount>;
  private session: AuthSession | null = null;

  constructor(config: AgentAuthConfig) {
    this.serverUrl = config.serverUrl.replace(/\/$/, '');
    this.apiKey = config.apiKey;
    this.account = privateKeyToAccount(config.privateKey);
  }

  /** The agent's Ethereum address */
  get address(): string {
    return this.account.address;
  }

  /** Current session (null if not authenticated) */
  get currentSession(): AuthSession | null {
    if (this.session && this.session.expiresAt * 1000 < Date.now()) {
      this.session = null;
    }
    return this.session;
  }

  /**
   * Authenticate with a site using AgentAuth.
   * Handles the full challenge → sign → verify flow in one call.
   * Returns a session with JWT token and sybil attestation.
   */
  async authenticate(): Promise<AuthSession> {
    // Step 1: Get challenge
    const challengeRes = await fetch(`${this.serverUrl}/api/challenge`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': this.apiKey,
      },
      body: JSON.stringify({ address: this.account.address }),
    });

    if (!challengeRes.ok) {
      const err = await challengeRes.json() as { error: string };
      throw new Error(`Challenge failed: ${err.error}`);
    }

    const challengeData = await challengeRes.json() as { challenge: string };
    const challenge = challengeData.challenge;

    // Step 2: Sign with agent wallet
    const signature = await this.account.signMessage({ message: challenge });

    // Step 3: Verify and get session
    const verifyRes = await fetch(`${this.serverUrl}/api/verify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': this.apiKey,
      },
      body: JSON.stringify({ message: challenge, signature }),
    });

    if (!verifyRes.ok) {
      const err = await verifyRes.json() as { error: string };
      throw new Error(`Verification failed: ${err.error}`);
    }

    const data = await verifyRes.json() as AuthSession;
    this.session = data;
    return data;
  }

  /**
   * Make an authenticated fetch request using the session JWT.
   * Automatically re-authenticates if the session has expired.
   */
  async fetch(url: string, options: RequestInit = {}): Promise<Response> {
    if (!this.currentSession) {
      await this.authenticate();
    }

    const headers = new Headers(options.headers);
    headers.set('Authorization', `Bearer ${this.session!.token}`);

    return fetch(url, { ...options, headers });
  }

  /**
   * Check sybil score for any Ethereum address (no auth required).
   */
  async checkScore(address: string): Promise<ScoreResult> {
    const res = await fetch(`${this.serverUrl}/api/score/${address}`);

    if (!res.ok) {
      const err = await res.json() as { error: string };
      throw new Error(`Score check failed: ${err.error}`);
    }

    return res.json() as Promise<ScoreResult>;
  }

  /**
   * Validate the current session token with the server.
   */
  async validateSession(): Promise<boolean> {
    if (!this.session) return false;

    const res = await fetch(`${this.serverUrl}/api/session`, {
      headers: { Authorization: `Bearer ${this.session.token}` },
    });

    return res.ok;
  }

  /** Clear the current session */
  logout(): void {
    this.session = null;
  }
}

/**
 * One-shot authenticate: create skill, authenticate, return session.
 * For agents that just need a token quickly.
 *
 *   const session = await authenticate({
 *     serverUrl: 'https://agent-auth-alpha.vercel.app',
 *     apiKey: 'aa_...',
 *     privateKey: '0x...',
 *   });
 */
export async function authenticate(config: AgentAuthConfig): Promise<AuthSession> {
  const skill = new AgentAuthSkill(config);
  return skill.authenticate();
}
