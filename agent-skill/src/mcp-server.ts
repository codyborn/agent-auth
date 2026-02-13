#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { AgentAuthSkill, registerSite } from './skill';

// Configuration from environment variables
const AGENTAUTH_SERVER_URL = process.env.AGENTAUTH_SERVER_URL || 'https://agent-auth-alpha.vercel.app';
const AGENTAUTH_API_KEY = process.env.AGENTAUTH_API_KEY || '';
const AGENT_PRIVATE_KEY = process.env.AGENT_PRIVATE_KEY || '';

let skill: AgentAuthSkill | null = null;

function getSkill(): AgentAuthSkill {
  if (!skill) {
    if (!AGENTAUTH_API_KEY) throw new Error('AGENTAUTH_API_KEY environment variable is required');
    if (!AGENT_PRIVATE_KEY) throw new Error('AGENT_PRIVATE_KEY environment variable is required');

    skill = new AgentAuthSkill({
      serverUrl: AGENTAUTH_SERVER_URL,
      apiKey: AGENTAUTH_API_KEY,
      privateKey: AGENT_PRIVATE_KEY as `0x${string}`,
    });
  }
  return skill;
}

const server = new McpServer({
  name: 'agentauth',
  version: '0.1.0',
});

// Tool: Register a new site
server.tool(
  'register_site',
  'Register a new site with AgentAuth. Requires wallet signature to prevent spam. Returns an API key for the site. Use this before authenticate if you need a new API key.',
  {
    domain: z.string().describe('Domain for the site (e.g. example.com)'),
    callbackUrls: z.string().describe('Comma-separated callback URLs'),
    minScore: z.number().min(0).max(100).default(0).describe('Minimum sybil score required (0-100)'),
  },
  async ({ domain, callbackUrls, minScore }) => {
    try {
      if (!AGENT_PRIVATE_KEY) throw new Error('AGENT_PRIVATE_KEY environment variable is required');
      const site = await registerSite({
        serverUrl: AGENTAUTH_SERVER_URL,
        privateKey: AGENT_PRIVATE_KEY as `0x${string}`,
        domain,
        callbackUrls: callbackUrls.split(',').map(u => u.trim()),
        minScore,
      });
      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            success: true,
            siteId: site.siteId,
            apiKey: site.apiKey,
            domain: site.domain,
            minScore: site.minScore,
            registeredBy: site.registeredBy,
            message: 'Save your API key - set it as AGENTAUTH_API_KEY to use authenticate.',
          }, null, 2),
        }],
      };
    } catch (err: any) {
      return {
        content: [{ type: 'text' as const, text: `Registration failed: ${err.message}` }],
        isError: true,
      };
    }
  }
);

// Tool: Authenticate with a site
server.tool(
  'authenticate',
  'Authenticate this agent with a site using AgentAuth. Signs a challenge with the agent wallet and verifies onchain identity. Returns a JWT token and sybil score attestation.',
  {},
  async () => {
    try {
      const s = getSkill();
      const session = await s.authenticate();
      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            success: true,
            address: session.address,
            sybilScore: session.sybilScore,
            sybilBreakdown: session.sybilBreakdown,
            token: session.token,
            expiresAt: new Date(session.expiresAt * 1000).toISOString(),
            attestation: {
              attester: session.attestation.attester,
              score: session.attestation.score,
              signature: session.attestation.signature,
            },
          }, null, 2),
        }],
      };
    } catch (err: any) {
      return {
        content: [{ type: 'text' as const, text: `Authentication failed: ${err.message}` }],
        isError: true,
      };
    }
  }
);

// Tool: Check sybil score for any address
server.tool(
  'check_sybil_score',
  'Check the sybil resistance score for any Ethereum address. Returns a score from 0-100 based on onchain history across Ethereum, Base, Optimism, Arbitrum, Polygon, and Monad.',
  { address: z.string().describe('Ethereum address to check (0x...)') },
  async ({ address }) => {
    try {
      const s = getSkill();
      const result = await s.checkScore(address);
      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify(result, null, 2),
        }],
      };
    } catch (err: any) {
      return {
        content: [{ type: 'text' as const, text: `Score check failed: ${err.message}` }],
        isError: true,
      };
    }
  }
);

// Tool: Get current session info
server.tool(
  'get_session',
  'Get the current AgentAuth session info including address, sybil score, and token expiry. Returns null if not authenticated.',
  {},
  async () => {
    try {
      const s = getSkill();
      const session = s.currentSession;
      if (!session) {
        return {
          content: [{ type: 'text' as const, text: 'Not authenticated. Use the authenticate tool first.' }],
        };
      }
      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            address: session.address,
            sybilScore: session.sybilScore,
            sybilBreakdown: session.sybilBreakdown,
            tokenExpires: new Date(session.expiresAt * 1000).toISOString(),
            isValid: session.expiresAt * 1000 > Date.now(),
          }, null, 2),
        }],
      };
    } catch (err: any) {
      return {
        content: [{ type: 'text' as const, text: `Failed to get session: ${err.message}` }],
        isError: true,
      };
    }
  }
);

// Tool: Make an authenticated request
server.tool(
  'authenticated_fetch',
  'Make an HTTP request with AgentAuth JWT token in the Authorization header. Automatically authenticates if no active session.',
  {
    url: z.string().describe('URL to fetch'),
    method: z.enum(['GET', 'POST', 'PUT', 'DELETE', 'PATCH']).default('GET').describe('HTTP method'),
    body: z.string().optional().describe('Request body (JSON string)'),
    headers: z.string().optional().describe('Additional headers as JSON string, e.g. {"X-Custom": "value"}'),
  },
  async ({ url, method, body, headers }) => {
    try {
      const s = getSkill();
      const res = await s.fetch(url, {
        method,
        body: body || undefined,
        headers: {
          ...(body ? { 'Content-Type': 'application/json' } : {}),
          ...(headers ? JSON.parse(headers) : {}),
        },
      });
      const responseText = await res.text();
      let responseBody: any;
      try { responseBody = JSON.parse(responseText); } catch { responseBody = responseText; }

      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            status: res.status,
            statusText: res.statusText,
            body: responseBody,
          }, null, 2),
        }],
      };
    } catch (err: any) {
      return {
        content: [{ type: 'text' as const, text: `Fetch failed: ${err.message}` }],
        isError: true,
      };
    }
  }
);

// Tool: Get agent wallet address
server.tool(
  'get_agent_address',
  'Get the Ethereum address of this agent\'s configured wallet.',
  {},
  async () => {
    try {
      const s = getSkill();
      return {
        content: [{ type: 'text' as const, text: s.address }],
      };
    } catch (err: any) {
      return {
        content: [{ type: 'text' as const, text: `Failed: ${err.message}` }],
        isError: true,
      };
    }
  }
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch(console.error);
