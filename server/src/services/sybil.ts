import { createPublicClient, http, formatEther, type PublicClient } from 'viem';
import { mainnet, base, optimism, arbitrum, polygon } from 'viem/chains';
import type { SybilScoreBreakdown } from '../types';

const CHAIN_MAP: Record<number, { chain: any; name: string }> = {
  1: { chain: mainnet, name: 'Ethereum' },
  8453: { chain: base, name: 'Base' },
  10: { chain: optimism, name: 'Optimism' },
  42161: { chain: arbitrum, name: 'Arbitrum' },
  137: { chain: polygon, name: 'Polygon' },
};

function getClient(chainId: number, rpcUrls: Record<number, string>): PublicClient {
  const rpcUrl = rpcUrls[chainId];
  const chainConfig = CHAIN_MAP[chainId];
  if (!chainConfig) throw new Error(`Unsupported chain: ${chainId}`);
  return createPublicClient({ chain: chainConfig.chain, transport: http(rpcUrl) }) as PublicClient;
}

// Score aggregated balance across all chains: 0-33 points
function scoreBalance(totalBalanceETH: number): number {
  if (totalBalanceETH >= 10) return 33;
  if (totalBalanceETH >= 1) return 28;
  if (totalBalanceETH >= 0.1) return 22;
  if (totalBalanceETH >= 0.01) return 16;
  if (totalBalanceETH >= 0.001) return 10;
  if (totalBalanceETH > 0) return 5;
  return 0;
}

// Score aggregated transaction count across all chains: 0-34 points
function scoreTxCount(totalTxCount: number): number {
  if (totalTxCount >= 500) return 34;
  if (totalTxCount >= 100) return 28;
  if (totalTxCount >= 50) return 22;
  if (totalTxCount >= 20) return 16;
  if (totalTxCount >= 5) return 10;
  if (totalTxCount >= 1) return 5;
  return 0;
}

// Score account age (estimated from total tx count): 0-33 points
// In production, query an indexer for first-tx timestamp
function scoreAccountAge(totalTxCount: number): number {
  if (totalTxCount >= 500) return 33;
  if (totalTxCount >= 100) return 28;
  if (totalTxCount >= 50) return 22;
  if (totalTxCount >= 20) return 16;
  if (totalTxCount >= 5) return 10;
  if (totalTxCount >= 1) return 5;
  return 0;
}

interface ChainResult {
  chainId: number;
  chainName: string;
  balanceETH: number;
  txCount: number;
}

export async function computeSybilScore(
  address: string,
  rpcUrls: Record<number, string>
): Promise<{
  breakdown: SybilScoreBreakdown;
  details: {
    totalBalanceETH: number;
    totalTransactionCount: number;
    chainsChecked: number;
    chainsWithActivity: number;
    perChain: ChainResult[];
  };
}> {
  const addr = address as `0x${string}`;
  const chainIds = Object.keys(CHAIN_MAP).map(Number).filter((id) => rpcUrls[id]);

  // Query all chains in parallel
  const chainResults = await Promise.allSettled(
    chainIds.map(async (chainId): Promise<ChainResult> => {
      const client = getClient(chainId, rpcUrls);
      const [balance, txCount] = await Promise.all([
        client.getBalance({ address: addr }),
        client.getTransactionCount({ address: addr }),
      ]);
      return {
        chainId,
        chainName: CHAIN_MAP[chainId].name,
        balanceETH: parseFloat(formatEther(balance)),
        txCount,
      };
    })
  );

  // Aggregate results
  let totalBalanceETH = 0;
  let totalTxCount = 0;
  let chainsWithActivity = 0;
  const perChain: ChainResult[] = [];

  for (const result of chainResults) {
    if (result.status === 'fulfilled') {
      const r = result.value;
      perChain.push(r);
      totalBalanceETH += r.balanceETH;
      totalTxCount += r.txCount;
      if (r.txCount > 0 || r.balanceETH > 0) chainsWithActivity++;
    }
  }

  const balanceScoreVal = scoreBalance(totalBalanceETH);
  const txCountScoreVal = scoreTxCount(totalTxCount);
  const accountAgeScoreVal = scoreAccountAge(totalTxCount);

  const breakdown: SybilScoreBreakdown = {
    balanceScore: balanceScoreVal,
    txCountScore: txCountScoreVal,
    accountAgeScore: accountAgeScoreVal,
    totalScore: balanceScoreVal + txCountScoreVal + accountAgeScoreVal,
  };

  return {
    breakdown,
    details: {
      totalBalanceETH,
      totalTransactionCount: totalTxCount,
      chainsChecked: chainIds.length,
      chainsWithActivity,
      perChain,
    },
  };
}
