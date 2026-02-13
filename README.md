# AgentAuth

**OAuth-like authentication for AI agents with onchain sybil resistance.**

AgentAuth lets websites authenticate AI agents using their Ethereum wallets, then scores their onchain history across multiple chains to prevent sybil attacks and abuse. Think "Sign In with Google" but for AI agents, with built-in trust scoring.

## Why AgentAuth?

As AI agents proliferate, websites need a way to:
- **Authenticate agents** without passwords or API keys
- **Prevent abuse** from bot farms and sybil attacks
- **Gate access** based on agent trustworthiness
- **Rate limit** based on verifiable onchain identity

AgentAuth solves this with a simple SDK that combines wallet-based authentication with multi-chain onchain sybil scoring.

## How It Works

```
                         0. Site registers domain + minScore → gets API key

Agent                    Website                   AgentAuth Server
  |                        |                            |
  |   1. Visit site        |                            |
  |----------------------->|                            |
  |                        |  2. Request challenge      |
  |                        |   (with API key)           |
  |                        |--------------------------->|
  |                        |  3. Return nonce + message |
  |                        |<---------------------------|
  |  4. Sign message       |                            |
  |<-----------------------|                            |
  |  5. Return signature   |                            |
  |----------------------->|  6. Verify sig + score     |
  |                        |   (all chains)             |
  |                        |--------------------------->|
  |                        |  7. Enforce minScore       |
  |                        |  8. JWT + sybil score      |
  |                        |<---------------------------|
  |  9. Grant access       |                            |
  |<-----------------------|                            |
```

## Sybil Score (0-100)

All signals are **aggregated across all supported chains** (Ethereum, Base, Optimism, Arbitrum, Polygon, Monad):

| Signal | What it checks | Max Points |
|--------|---------------|------------|
| **Balance** | Total native token holdings across all chains | 33 |
| **Transaction Count** | Total transactions across all chains | 34 |
| **Account Age** | Estimated account maturity | 33 |

The minimum score is **set by the site developer during registration** and enforced server-side. Clients cannot override it.

## Quick Start

### 1. Register Your Site (requires wallet signature)

Site registration is authenticated via AgentAuth itself to prevent spam. You prove wallet ownership and the server checks your onchain identity before issuing an API key.

**Using the Agent Skill (recommended):**

```typescript
import { registerSite } from '@agent-auth/agent-skill';

const site = await registerSite({
  serverUrl: 'https://agent-auth-alpha.vercel.app',
  privateKey: '0x...',  // Your Ethereum private key
  domain: 'example.com',
  callbackUrls: ['https://example.com/callback'],
  minScore: 25,
});
console.log('API Key:', site.apiKey);  // Save this!
```

**Using curl (3 steps):**

```bash
# Step 1: Get a registration challenge
curl -X POST https://agent-auth-alpha.vercel.app/api/register/challenge \
  -H 'Content-Type: application/json' \
  -d '{ "address": "0xYOUR_WALLET_ADDRESS" }'
# Returns: { challenge, nonce, ... }

# Step 2: Sign the challenge with your wallet (use ethers.js, viem, etc.)

# Step 3: Register with the signed challenge
curl -X POST https://agent-auth-alpha.vercel.app/api/sites/register \
  -H 'Content-Type: application/json' \
  -d '{
    "domain": "example.com",
    "callbackUrls": ["https://example.com/callback"],
    "minScore": 25,
    "message": "<signed challenge from step 1>",
    "signature": "0x<signature from step 2>"
  }'
# Returns: { siteId, apiKey, registeredBy, ... }
```

### 2. Integrate (AI Agents - Recommended)

The Agent Skill handles the full auth flow in a single call:

```typescript
import { AgentAuthSkill } from '@agent-auth/agent-skill';

const agent = new AgentAuthSkill({
  serverUrl: 'https://agent-auth-alpha.vercel.app',
  apiKey: 'aa_your_site_api_key',
  privateKey: '0x...',  // Agent's Ethereum private key
});

// One-call authentication
const session = await agent.authenticate();
console.log(`Score: ${session.sybilScore}/100`);

// Make authenticated requests to protected APIs
const res = await agent.fetch('https://protected-api.com/data');
```

### 3. MCP Server (for Claude, ChatGPT, etc.)

Add AgentAuth as an MCP tool server so any MCP-compatible AI agent can authenticate:

```json
{
  "mcpServers": {
    "agentauth": {
      "command": "npx",
      "args": ["@agent-auth/agent-skill"],
      "env": {
        "AGENTAUTH_SERVER_URL": "https://agent-auth-alpha.vercel.app",
        "AGENTAUTH_API_KEY": "aa_your_site_api_key",
        "AGENT_PRIVATE_KEY": "0x..."
      }
    }
  }
}
```

Available MCP tools:
- `register_site` - Register a new site (wallet signature required)
- `authenticate` - Full wallet auth flow, returns JWT + sybil attestation
- `check_sybil_score` - Look up any address's sybil score
- `authenticated_fetch` - Make HTTP requests with the auth token
- `get_session` - Check current session status
- `get_agent_address` - Get the configured wallet address

### 4. Integrate (Browser)

```typescript
import { AgentAuthClient, BrowserWalletProvider } from '@agent-auth/sdk';

const auth = new AgentAuthClient({
  serverUrl: 'https://agent-auth-alpha.vercel.app',
  apiKey: 'aa_your_site_api_key',
});

const session = await auth.login(new BrowserWalletProvider());
console.log(`Authenticated: ${session.address}`);
console.log(`Sybil Score: ${session.sybilScore}/100`);
console.log(`JWT: ${session.token}`);
```

### 5. Integrate (Node.js with SDK)

```typescript
import { AgentAuthClient, PrivateKeyWalletProvider } from '@agent-auth/sdk';
import { privateKeyToAccount } from 'viem/accounts';

const account = privateKeyToAccount(process.env.AGENT_PRIVATE_KEY);
const wallet = new PrivateKeyWalletProvider(
  account.address,
  (msg) => account.signMessage({ message: msg })
);

const auth = new AgentAuthClient({
  serverUrl: 'https://agent-auth-alpha.vercel.app',
  apiKey: 'aa_your_site_api_key',
});

const session = await auth.login(wallet);
// Use session.token for subsequent API calls
```

### Check Any Address (No Auth Required)

```bash
curl https://agent-auth-alpha.vercel.app/api/score/0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045
# { sybilScore: 100, breakdown: { balanceScore: 33, txCountScore: 34, accountAgeScore: 33 } }
```

## API Reference

### `POST /api/register/challenge`

Get a registration challenge for site registration. **No API key required** - this bootstraps the auth flow.

**Body:**
```json
{
  "address": "0x..."
}
```

**Response:**
```json
{
  "challenge": "AgentAuth wants you to sign in...",
  "nonce": "abc123...",
  "issuedAt": "2026-01-01T00:00:00Z",
  "expirationTime": "2026-01-01T00:05:00Z"
}
```

### `POST /api/sites/register`

Register a new site. **Requires a signed registration challenge** to prevent spam. Returns an API key for challenge/verify endpoints.

**Body:**
```json
{
  "domain": "example.com",
  "callbackUrls": ["https://example.com/callback"],
  "minScore": 25,
  "message": "AgentAuth wants you to sign in...",
  "signature": "0x..."
}
```

**Response:**
```json
{
  "siteId": "site_abc123...",
  "apiKey": "aa_xyz789...",
  "domain": "example.com",
  "callbackUrls": ["https://example.com/callback"],
  "minScore": 25,
  "registeredBy": "0x...",
  "createdAt": "2026-01-01T00:00:00Z"
}
```

### `POST /api/challenge`

Request a new authentication challenge. **Requires `x-api-key` header.**

**Headers:** `x-api-key: aa_your_api_key`

**Body:**
```json
{
  "address": "0x..."
}
```

**Response:**
```json
{
  "challenge": "example.com wants you to sign in...",
  "nonce": "abc123...",
  "issuedAt": "2026-01-01T00:00:00Z",
  "expirationTime": "2026-01-01T00:05:00Z"
}
```

### `POST /api/verify`

Verify a signed challenge and get sybil score. Server enforces the site's `minScore` - returns 403 if below threshold. **Requires `x-api-key` header.**

**Headers:** `x-api-key: aa_your_api_key`

**Body:**
```json
{
  "message": "example.com wants you to sign in...",
  "signature": "0x..."
}
```

**Response (success):**
```json
{
  "success": true,
  "address": "0x...",
  "sybilScore": 67,
  "sybilBreakdown": {
    "balanceScore": 0,
    "txCountScore": 34,
    "accountAgeScore": 33,
    "totalScore": 67
  },
  "sybilDetails": {
    "totalBalanceETH": 0,
    "totalTransactionCount": 102390,
    "chainsChecked": 5,
    "chainsWithActivity": 5,
    "perChain": [
      { "chainId": 1, "chainName": "Ethereum", "balanceETH": 0, "txCount": 4829 },
      { "chainId": 8453, "chainName": "Base", "balanceETH": 0, "txCount": 41930 }
    ]
  },
  "token": "eyJ...",
  "expiresAt": 1704153600
}
```

**Response (below minScore):**
```json
{
  "error": "Sybil score below site minimum",
  "sybilScore": 10,
  "requiredScore": 25
}
```

### `GET /api/score/:address`

Check sybil score for any address (no API key required). Always aggregated across all chains.

### `GET /api/session`

Validate a session token. **Headers:** `Authorization: Bearer <token>`

## Running Locally

```bash
# Install dependencies
npm install

# Start the server (includes demo site)
npm run dev

# Open http://localhost:3001 for the demo
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3001` | Server port |
| `JWT_SECRET` | `agent-auth-dev-secret...` | JWT signing secret |
| `JWT_EXPIRES_IN` | `24h` | JWT expiration |
| `CHALLENGE_TTL` | `300` | Challenge validity (seconds) |
| `RPC_ETH_MAINNET` | Public RPC | Ethereum mainnet RPC |
| `RPC_BASE` | Public RPC | Base RPC |
| `RPC_OPTIMISM` | Public RPC | Optimism RPC |
| `RPC_ARBITRUM` | Public RPC | Arbitrum RPC |
| `RPC_POLYGON` | Public RPC | Polygon RPC |
| `RPC_MONAD` | Public RPC | Monad RPC |
| `REGISTRATION_MIN_SCORE` | `0` | Min sybil score to register a site |

## Architecture

```
agent-auth/
├── server/           # Express API server
│   └── src/
│       ├── index.ts           # Server entry point
│       ├── types.ts           # TypeScript types
│       ├── routes/            # API route handlers
│       └── services/          # Sybil scoring, attestation, JWT, etc.
├── sdk/              # TypeScript SDK for website integration
│   └── src/
│       ├── client.ts          # AgentAuthClient + wallet providers
│       └── types.ts           # SDK types
├── agent-skill/      # Agent integration package
│   └── src/
│       ├── skill.ts           # AgentAuthSkill - one-call auth for agents
│       └── mcp-server.ts      # MCP tool server for AI agents
├── demo/             # Demo website
│   └── public/
│       ├── index.html         # Interactive demo
│       └── app.js             # Demo app logic
├── api/              # Vercel serverless function
│   └── index.js               # Standalone API (production)
└── public/           # Static files (Vercel)
```

## Protocol Compatibility

AgentAuth uses **SIWE-compatible** (Sign In With Ethereum / ERC-4361) message format, making it compatible with existing Ethereum wallet infrastructure. It extends the concept with:

- **Multi-chain sybil scoring** aggregated across all supported chains
- **Site registration** with developer-controlled minimum scores
- **Server-enforced access control** - clients cannot bypass minScore
- **JWT tokens** with embedded sybil data for stateless verification

## Supported Chains

All sybil scores are aggregated across:
- Ethereum Mainnet (Chain ID: 1)
- Base (Chain ID: 8453)
- Optimism (Chain ID: 10)
- Arbitrum (Chain ID: 42161)
- Polygon (Chain ID: 137)
- Monad (Chain ID: 143)

## Built For

[Moltiverse Hackathon](https://moltiverse.dev) - February 2026

## License

MIT
