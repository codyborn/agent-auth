// Vercel serverless function - wraps the Express app
// Using .js to avoid TypeScript compilation issues with Vercel's builder
const express = require('express');
const cors = require('cors');
const { createPublicClient, http, formatEther, verifyMessage, isAddress, hashTypedData } = require('viem');
const { mainnet, base, optimism, arbitrum, polygon } = require('viem/chains');
const { privateKeyToAccount } = require('viem/accounts');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// ---- Config ----
const DEV_ATTESTATION_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
const config = {
  jwtSecret: process.env.JWT_SECRET || 'agent-auth-dev-secret-change-in-production',
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || '24h',
  challengeTTL: parseInt(process.env.CHALLENGE_TTL || '300'),
  attestationPrivateKey: process.env.ATTESTATION_PRIVATE_KEY || DEV_ATTESTATION_KEY,
  rpcUrls: {
    1: process.env.RPC_ETH_MAINNET || 'https://eth.drpc.org',
    8453: process.env.RPC_BASE || 'https://base.drpc.org',
    10: process.env.RPC_OPTIMISM || 'https://optimism.drpc.org',
    42161: process.env.RPC_ARBITRUM || 'https://arbitrum.drpc.org',
    137: process.env.RPC_POLYGON || 'https://polygon.drpc.org',
    143: process.env.RPC_MONAD || 'https://monad-mainnet.drpc.org',
  },
};

// ---- Chain Map ----
const monad = {
  id: 143,
  name: 'Monad',
  nativeCurrency: { name: 'Monad', symbol: 'MON', decimals: 18 },
  rpcUrls: { default: { http: ['https://monad-mainnet.drpc.org'] } },
  blockExplorers: { default: { name: 'Monad Explorer', url: 'https://explorer.monad.xyz' } },
};

const CHAIN_MAP = {
  1: { chain: mainnet, name: 'Ethereum' },
  8453: { chain: base, name: 'Base' },
  10: { chain: optimism, name: 'Optimism' },
  42161: { chain: arbitrum, name: 'Arbitrum' },
  137: { chain: polygon, name: 'Polygon' },
  143: { chain: monad, name: 'Monad' },
};

function getClient(chainId) {
  const rpcUrl = config.rpcUrls[chainId];
  const chainConfig = CHAIN_MAP[chainId];
  if (!chainConfig) throw new Error(`Unsupported chain: ${chainId}`);
  return createPublicClient({ chain: chainConfig.chain, transport: http(rpcUrl) });
}

// ---- In-memory stores ----
const challenges = new Map();
const sites = new Map();
const sitesByApiKey = new Map();
const attestationCache = new Map();

// ---- Sites ----
function registerSite(req) {
  const siteId = 'site_' + crypto.randomBytes(12).toString('hex');
  const apiKey = 'aa_' + crypto.randomBytes(24).toString('hex');
  const site = {
    siteId, apiKey,
    domain: req.domain,
    callbackUrls: req.callbackUrls,
    minScore: Math.max(0, Math.min(100, req.minScore)),
    createdAt: new Date().toISOString(),
  };
  sites.set(siteId, site);
  sitesByApiKey.set(apiKey, site);
  return site;
}

// ---- Challenge ----
function createChallenge(siteId, domain, uri, address, ttl) {
  const nonce = crypto.randomBytes(16).toString('hex');
  const issuedAt = new Date().toISOString();
  const expirationTime = new Date(Date.now() + ttl * 1000).toISOString();
  const addressLine = address || '<agent-wallet-address>';
  const message = [
    `${domain} wants you to sign in with your Ethereum account:`,
    addressLine, '',
    'Sign in with AgentAuth - Verified Agent Authentication', '',
    `URI: ${uri}`, `Version: 1`,
    `Nonce: ${nonce}`, `Issued At: ${issuedAt}`, `Expiration Time: ${expirationTime}`,
  ].join('\n');
  const challenge = { nonce, domain, uri, issuedAt, expirationTime, message, siteId };
  challenges.set(nonce, { challenge, expiresAt: Date.now() + ttl * 1000 });
  return challenge;
}

function validateChallenge(nonce) {
  const entry = challenges.get(nonce);
  if (!entry) return null;
  if (entry.expiresAt < Date.now()) { challenges.delete(nonce); return null; }
  challenges.delete(nonce);
  return entry.challenge;
}

// ---- Sybil ----
function scoreBalance(v) { if (v >= 10) return 33; if (v >= 1) return 28; if (v >= 0.1) return 22; if (v >= 0.01) return 16; if (v >= 0.001) return 10; if (v > 0) return 5; return 0; }
function scoreTxCount(v) { if (v >= 500) return 34; if (v >= 100) return 28; if (v >= 50) return 22; if (v >= 20) return 16; if (v >= 5) return 10; if (v >= 1) return 5; return 0; }
function scoreAccountAge(v) { if (v >= 500) return 33; if (v >= 100) return 28; if (v >= 50) return 22; if (v >= 20) return 16; if (v >= 5) return 10; if (v >= 1) return 5; return 0; }

async function computeSybilScore(address) {
  const addr = address;
  const chainIds = Object.keys(CHAIN_MAP).map(Number).filter(id => config.rpcUrls[id]);
  const results = await Promise.allSettled(
    chainIds.map(async (chainId) => {
      const client = getClient(chainId);
      const [balance, txCount] = await Promise.all([
        client.getBalance({ address: addr }),
        client.getTransactionCount({ address: addr }),
      ]);
      return { chainId, chainName: CHAIN_MAP[chainId].name, balanceETH: parseFloat(formatEther(balance)), txCount };
    })
  );
  let totalBalanceETH = 0, totalTxCount = 0, chainsWithActivity = 0;
  const perChain = [];
  for (const r of results) {
    if (r.status === 'fulfilled') {
      perChain.push(r.value);
      totalBalanceETH += r.value.balanceETH;
      totalTxCount += r.value.txCount;
      if (r.value.txCount > 0 || r.value.balanceETH > 0) chainsWithActivity++;
    }
  }
  const bs = scoreBalance(totalBalanceETH), ts = scoreTxCount(totalTxCount), as_ = scoreAccountAge(totalTxCount);
  return {
    breakdown: { balanceScore: bs, txCountScore: ts, accountAgeScore: as_, totalScore: bs + ts + as_ },
    details: { totalBalanceETH, totalTransactionCount: totalTxCount, chainsChecked: chainIds.length, chainsWithActivity, perChain },
  };
}

// ---- Attestation ----
const EIP712_DOMAIN = { name: 'AgentAuth', version: '1' };
const EIP712_TYPES = {
  SybilAttestation: [
    { name: 'subject', type: 'address' }, { name: 'score', type: 'uint8' },
    { name: 'balanceScore', type: 'uint8' }, { name: 'txCountScore', type: 'uint8' },
    { name: 'accountAgeScore', type: 'uint8' }, { name: 'issuedAt', type: 'uint256' },
    { name: 'expiresAt', type: 'uint256' },
  ],
};

let serverAccount = null;
function getServerAccount() {
  if (!serverAccount) serverAccount = privateKeyToAccount(config.attestationPrivateKey);
  return serverAccount;
}

function getCachedAttestation(address) {
  const cached = attestationCache.get(address.toLowerCase());
  if (!cached || cached.expiresAt * 1000 < Date.now()) { attestationCache.delete(address.toLowerCase()); return null; }
  return cached;
}

async function createAttestation(address, breakdown) {
  const account = getServerAccount();
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + 86400;
  const signature = await account.signTypedData({
    domain: EIP712_DOMAIN, types: EIP712_TYPES, primaryType: 'SybilAttestation',
    message: { subject: address, score: breakdown.totalScore, balanceScore: breakdown.balanceScore, txCountScore: breakdown.txCountScore, accountAgeScore: breakdown.accountAgeScore, issuedAt: BigInt(now), expiresAt: BigInt(expiresAt) },
  });
  const att = { subject: address, score: breakdown.totalScore, balanceScore: breakdown.balanceScore, txCountScore: breakdown.txCountScore, accountAgeScore: breakdown.accountAgeScore, issuedAt: now, expiresAt, attester: account.address, signature };
  attestationCache.set(address.toLowerCase(), att);
  return att;
}

// ---- Message Parser ----
function parseMessage(message) {
  try {
    const lines = message.split('\n');
    const address = lines[1]?.trim();
    const uri = lines.find(l => l.startsWith('URI:'))?.replace('URI: ', '').trim();
    const nonce = lines.find(l => l.startsWith('Nonce:'))?.replace('Nonce: ', '').trim();
    const issuedAt = lines.find(l => l.startsWith('Issued At:'))?.replace('Issued At: ', '').trim();
    const expirationTime = lines.find(l => l.startsWith('Expiration Time:'))?.replace('Expiration Time: ', '').trim();
    const domain = lines[0]?.replace(' wants you to sign in with your Ethereum account:', '').trim();
    if (!address || !nonce || !domain) return null;
    return { domain, address, uri: uri || '', nonce, issuedAt: issuedAt || '', expirationTime: expirationTime || '' };
  } catch { return null; }
}

// ---- Express App ----
const app = express();
app.use(cors());
app.use(express.json());

// Health
app.get('/api/health', (_req, res) => res.json({ status: 'ok', version: '0.1.0' }));

// Sites
app.post('/api/sites/register', (req, res) => {
  const { domain, callbackUrls, minScore } = req.body;
  if (!domain) return res.status(400).json({ error: 'domain is required' });
  if (!callbackUrls || !Array.isArray(callbackUrls) || callbackUrls.length === 0) return res.status(400).json({ error: 'callbackUrls must be a non-empty array' });
  if (minScore === undefined || typeof minScore !== 'number' || minScore < 0 || minScore > 100) return res.status(400).json({ error: 'minScore must be a number between 0 and 100' });
  const site = registerSite({ domain, callbackUrls, minScore });
  res.status(201).json({ ...site, message: 'Save your API key - it cannot be retrieved later.' });
});

app.get('/api/sites/me', (req, res) => {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey) return res.status(401).json({ error: 'x-api-key header is required' });
  const site = sitesByApiKey.get(apiKey);
  if (!site) return res.status(401).json({ error: 'Invalid API key' });
  res.json({ siteId: site.siteId, domain: site.domain, callbackUrls: site.callbackUrls, minScore: site.minScore, createdAt: site.createdAt });
});

// Challenge
app.post('/api/challenge', (req, res) => {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey) return res.status(401).json({ error: 'x-api-key header is required. Register your site at POST /api/sites/register first.' });
  const site = sitesByApiKey.get(apiKey);
  if (!site) return res.status(401).json({ error: 'Invalid API key' });
  const { address } = req.body;
  const challenge = createChallenge(site.siteId, site.domain, `https://${site.domain}`, address, config.challengeTTL);
  res.json({ challenge: challenge.message, nonce: challenge.nonce, issuedAt: challenge.issuedAt, expirationTime: challenge.expirationTime });
});

// Verify
app.post('/api/verify', async (req, res) => {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey) return res.status(401).json({ error: 'x-api-key header is required' });
  const site = sitesByApiKey.get(apiKey);
  if (!site) return res.status(401).json({ error: 'Invalid API key' });

  const { message, signature } = req.body;
  if (!message || !signature) return res.status(400).json({ error: 'message and signature are required' });

  const parsed = parseMessage(message);
  if (!parsed) return res.status(400).json({ error: 'Invalid message format' });

  const challenge = validateChallenge(parsed.nonce);
  if (!challenge) return res.status(401).json({ error: 'Invalid or expired challenge nonce' });
  if (challenge.siteId !== site.siteId) return res.status(401).json({ error: 'Challenge does not belong to this site' });
  if (new Date(parsed.expirationTime) < new Date()) return res.status(401).json({ error: 'Challenge has expired' });

  let valid;
  try { valid = await verifyMessage({ address: parsed.address, message, signature }); }
  catch { return res.status(401).json({ error: 'Signature verification failed' }); }
  if (!valid) return res.status(401).json({ error: 'Invalid signature' });

  let sybilResult, attestation;
  const cached = getCachedAttestation(parsed.address);
  if (cached) {
    sybilResult = { breakdown: { balanceScore: cached.balanceScore, txCountScore: cached.txCountScore, accountAgeScore: cached.accountAgeScore, totalScore: cached.score }, details: null };
    attestation = cached;
  } else {
    try { sybilResult = await computeSybilScore(parsed.address); }
    catch (err) {
      console.error('Sybil check error:', err);
      sybilResult = { breakdown: { balanceScore: 0, txCountScore: 0, accountAgeScore: 0, totalScore: 0 }, details: { totalBalanceETH: 0, totalTransactionCount: 0, chainsChecked: 0, chainsWithActivity: 0, perChain: [] } };
    }
    attestation = await createAttestation(parsed.address, sybilResult.breakdown);
  }

  if (sybilResult.breakdown.totalScore < site.minScore) {
    return res.status(403).json({ error: 'Sybil score below site minimum', sybilScore: sybilResult.breakdown.totalScore, requiredScore: site.minScore, sybilBreakdown: sybilResult.breakdown });
  }

  const token = jwt.sign({ address: parsed.address, siteId: site.siteId, sybilScore: sybilResult.breakdown.totalScore, sybilBreakdown: sybilResult.breakdown }, config.jwtSecret, { expiresIn: config.jwtExpiresIn });
  const decoded = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());

  res.json({
    success: true, address: parsed.address,
    sybilScore: sybilResult.breakdown.totalScore, sybilBreakdown: sybilResult.breakdown,
    ...(sybilResult.details ? { sybilDetails: sybilResult.details } : {}),
    token, expiresAt: decoded.exp,
    attestation: { subject: attestation.subject, score: attestation.score, balanceScore: attestation.balanceScore, txCountScore: attestation.txCountScore, accountAgeScore: attestation.accountAgeScore, issuedAt: attestation.issuedAt, expiresAt: attestation.expiresAt, attester: attestation.attester, signature: attestation.signature },
  });
});

// Score (public)
app.get('/api/score/:address', async (req, res) => {
  const { address } = req.params;
  if (!isAddress(address)) return res.status(400).json({ error: 'Invalid Ethereum address' });
  try {
    const result = await computeSybilScore(address);
    res.json({ address, sybilScore: result.breakdown.totalScore, sybilBreakdown: result.breakdown, details: result.details });
  } catch (err) {
    console.error('Sybil score error:', err);
    res.status(500).json({ error: 'Failed to compute sybil score', message: err.message });
  }
});

// Session
app.get('/api/session', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) return res.status(401).json({ error: 'Missing or invalid Authorization header' });
  try {
    const payload = jwt.verify(authHeader.slice(7), config.jwtSecret);
    res.json({ valid: true, address: payload.address, siteId: payload.siteId, sybilScore: payload.sybilScore, sybilBreakdown: payload.sybilBreakdown, expiresAt: payload.exp });
  } catch { res.status(401).json({ error: 'Invalid or expired token' }); }
});

module.exports = app;
