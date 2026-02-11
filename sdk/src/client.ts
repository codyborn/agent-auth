import type { AgentAuthOptions, AgentAuthSession, ChallengeResponse } from './types';

export class AgentAuthClient {
  private serverUrl: string;
  private apiKey: string;
  private session: AgentAuthSession | null = null;

  constructor(options: AgentAuthOptions) {
    this.serverUrl = options.serverUrl.replace(/\/$/, '');
    this.apiKey = options.apiKey;
  }

  // Step 1: Request a challenge from the server
  async getChallenge(address?: string): Promise<ChallengeResponse> {
    const res = await fetch(`${this.serverUrl}/api/challenge`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': this.apiKey,
      },
      body: JSON.stringify({ address }),
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Failed to get challenge');
    }

    return res.json();
  }

  // Step 2: Verify a signed challenge
  async verify(message: string, signature: string): Promise<AgentAuthSession> {
    const res = await fetch(`${this.serverUrl}/api/verify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': this.apiKey,
      },
      body: JSON.stringify({ message, signature }),
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Verification failed');
    }

    const data = await res.json();
    this.session = data;
    return data;
  }

  // Full flow: get challenge, sign with wallet provider, verify
  async login(walletProvider: WalletProvider): Promise<AgentAuthSession> {
    const accounts = await walletProvider.getAccounts();
    if (accounts.length === 0) {
      throw new Error('No accounts available');
    }
    const address = accounts[0];

    const challenge = await this.getChallenge(address);
    const signature = await walletProvider.signMessage(challenge.challenge, address);
    return this.verify(challenge.challenge, signature);
  }

  // Check sybil score for any address (no API key required)
  async checkScore(address: string): Promise<{
    address: string;
    sybilScore: number;
    sybilBreakdown: AgentAuthSession['sybilBreakdown'];
    details: AgentAuthSession['sybilDetails'];
  }> {
    const res = await fetch(`${this.serverUrl}/api/score/${address}`);

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Failed to check score');
    }

    return res.json();
  }

  // Validate an existing session token
  async validateSession(token?: string): Promise<AgentAuthSession | null> {
    const t = token || this.session?.token;
    if (!t) return null;

    const res = await fetch(`${this.serverUrl}/api/session`, {
      headers: { Authorization: `Bearer ${t}` },
    });

    if (!res.ok) {
      this.session = null;
      return null;
    }

    return res.json();
  }

  getSession(): AgentAuthSession | null {
    return this.session;
  }

  clearSession(): void {
    this.session = null;
  }
}

// Interface for wallet providers (MetaMask, WalletConnect, agent wallets, etc.)
export interface WalletProvider {
  getAccounts(): Promise<string[]>;
  signMessage(message: string, address: string): Promise<string>;
}

// Built-in wallet provider for browser wallets (MetaMask, etc.)
export class BrowserWalletProvider implements WalletProvider {
  private ethereum: any;

  constructor() {
    if (typeof window !== 'undefined' && (window as any).ethereum) {
      this.ethereum = (window as any).ethereum;
    } else {
      throw new Error('No browser wallet detected. Install MetaMask or a compatible wallet.');
    }
  }

  async getAccounts(): Promise<string[]> {
    const accounts = await this.ethereum.request({ method: 'eth_requestAccounts' });
    return accounts;
  }

  async signMessage(message: string, address: string): Promise<string> {
    const signature = await this.ethereum.request({
      method: 'personal_sign',
      params: [message, address],
    });
    return signature;
  }
}

// Wallet provider for agents using a private key (viem-based)
export class PrivateKeyWalletProvider implements WalletProvider {
  private address: string;
  private signFn: (message: string) => Promise<string>;

  constructor(address: string, signFn: (message: string) => Promise<string>) {
    this.address = address;
    this.signFn = signFn;
  }

  async getAccounts(): Promise<string[]> {
    return [this.address];
  }

  async signMessage(message: string, _address: string): Promise<string> {
    return this.signFn(message);
  }
}
