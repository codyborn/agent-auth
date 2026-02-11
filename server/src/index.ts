import express from 'express';
import cors from 'cors';
import path from 'path';
import { challengeRouter } from './routes/challenge';
import { verifyRouter } from './routes/verify';
import { scoreRouter } from './routes/score';
import { sessionRouter } from './routes/session';
import { sitesRouter } from './routes/sites';
import type { AgentAuthConfig } from './types';

// Default dev key - DO NOT use in production
const DEV_ATTESTATION_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';

const config: AgentAuthConfig = {
  jwtSecret: process.env.JWT_SECRET || 'agent-auth-dev-secret-change-in-production',
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || '24h',
  challengeTTL: parseInt(process.env.CHALLENGE_TTL || '300'), // 5 minutes
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

const app = express();
const PORT = parseInt(process.env.PORT || '3001');

// Middleware
app.use(cors());
app.use(express.json());

// Serve demo static files
app.use(express.static(path.join(__dirname, '../../demo/public')));

// API routes
app.use('/api/sites', sitesRouter(config));
app.use('/api/challenge', challengeRouter(config));
app.use('/api/verify', verifyRouter(config));
app.use('/api/score', scoreRouter(config));
app.use('/api/session', sessionRouter(config));

// Health check
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', version: '0.1.0' });
});

// Serve demo for all non-API routes
app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, '../../demo/public/index.html'));
});

app.listen(PORT, () => {
  console.log(`\n  AgentAuth server running at http://localhost:${PORT}`);
  console.log(`  Demo site: http://localhost:${PORT}`);
  console.log(`  API: http://localhost:${PORT}/api\n`);
});
