import { Router, type Request, type Response } from 'express';
import { createPublicClient, http, parseEther, parseUnits, decodeEventLog, type PublicClient } from 'viem';
import { mainnet, base, optimism, arbitrum, polygon } from 'viem/chains';
import { isTxHashUsed, recordDonationBoost } from '../services/boost';
import type { AgentAuthConfig } from '../types';

const DONATION_WALLET = (process.env.DONATION_WALLET || '0x24EcD23096fCF03A15ee8a6FE63F24345Cc4BA46').toLowerCase();
const DONATION_BOOST_POINTS = parseInt(process.env.DONATION_BOOST_POINTS || '50');
const DONATION_MIN_ETH = process.env.DONATION_MIN_ETH || '0.001';
const DONATION_MIN_USDC = process.env.DONATION_MIN_USDC || '1';

// USDC contracts per chain
const USDC_CONTRACTS: Record<number, string> = {
  1: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
  8453: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
  10: '0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85',
  42161: '0xaf88d065e77c8cC2239327C5EDb3A432268e5831',
  137: '0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359',
};

// ERC-20 Transfer event ABI
const transferEventAbi = [
  {
    type: 'event',
    name: 'Transfer',
    inputs: [
      { name: 'from', type: 'address', indexed: true },
      { name: 'to', type: 'address', indexed: true },
      { name: 'value', type: 'uint256', indexed: false },
    ],
  },
] as const;

const monad = {
  id: 143,
  name: 'Monad',
  nativeCurrency: { name: 'Monad', symbol: 'MON', decimals: 18 },
  rpcUrls: { default: { http: ['https://monad-mainnet.drpc.org'] } },
  blockExplorers: { default: { name: 'Monad Explorer', url: 'https://explorer.monad.xyz' } },
} as const;

const CHAIN_MAP: Record<number, { chain: any; name: string }> = {
  1: { chain: mainnet, name: 'Ethereum' },
  8453: { chain: base, name: 'Base' },
  10: { chain: optimism, name: 'Optimism' },
  42161: { chain: arbitrum, name: 'Arbitrum' },
  137: { chain: polygon, name: 'Polygon' },
  143: { chain: monad, name: 'Monad' },
};

function getClient(chainId: number, rpcUrls: Record<number, string>): PublicClient {
  const rpcUrl = rpcUrls[chainId];
  const chainConfig = CHAIN_MAP[chainId];
  if (!chainConfig) throw new Error(`Unsupported chain: ${chainId}`);
  return createPublicClient({ chain: chainConfig.chain, transport: http(rpcUrl) }) as PublicClient;
}

export function boostRouter(config: AgentAuthConfig): Router {
  const router = Router();

  // GET /api/boost/info - Return donation requirements
  router.get('/info', (_req: Request, res: Response) => {
    res.json({
      wallet: DONATION_WALLET,
      boostPoints: DONATION_BOOST_POINTS,
      minETH: DONATION_MIN_ETH,
      minUSDC: DONATION_MIN_USDC,
      supportedChains: Object.entries(CHAIN_MAP).map(([id, { name }]) => ({
        chainId: Number(id),
        name,
      })),
      usdcContracts: USDC_CONTRACTS,
    });
  });

  // POST /api/boost - Verify a donation tx and grant score boost
  router.post('/', async (req: Request, res: Response) => {
    const { txHash, chainId } = req.body;

    if (!txHash || typeof txHash !== 'string') {
      res.status(400).json({ error: 'txHash is required' });
      return;
    }

    if (!chainId || typeof chainId !== 'number') {
      res.status(400).json({ error: 'chainId is required (number)' });
      return;
    }

    if (!CHAIN_MAP[chainId]) {
      res.status(400).json({ error: `Unsupported chain: ${chainId}` });
      return;
    }

    if (!config.rpcUrls[chainId]) {
      res.status(400).json({ error: `No RPC configured for chain ${chainId}` });
      return;
    }

    if (isTxHashUsed(txHash)) {
      res.status(409).json({ error: 'Transaction hash already used for a boost' });
      return;
    }

    let client: PublicClient;
    try {
      client = getClient(chainId, config.rpcUrls);
    } catch {
      res.status(400).json({ error: `Failed to connect to chain ${chainId}` });
      return;
    }

    // Fetch tx and receipt
    let tx: any;
    let receipt: any;
    try {
      [tx, receipt] = await Promise.all([
        client.getTransaction({ hash: txHash as `0x${string}` }),
        client.getTransactionReceipt({ hash: txHash as `0x${string}` }),
      ]);
    } catch (err: any) {
      res.status(404).json({ error: 'Transaction not found or not yet confirmed', details: err.message });
      return;
    }

    // Verify tx succeeded
    if (receipt.status !== 'success') {
      res.status(400).json({ error: 'Transaction was not successful' });
      return;
    }

    const sender = tx.from.toLowerCase();
    const minETHWei = parseEther(DONATION_MIN_ETH);
    const minUSDCUnits = parseUnits(DONATION_MIN_USDC, 6); // USDC has 6 decimals

    // Check if ETH transfer to donation wallet
    const isETHDonation =
      tx.to?.toLowerCase() === DONATION_WALLET &&
      tx.value >= minETHWei;

    // Check if USDC transfer to donation wallet
    let isUSDCDonation = false;
    const usdcAddress = USDC_CONTRACTS[chainId];
    if (usdcAddress && tx.to?.toLowerCase() === usdcAddress.toLowerCase()) {
      for (const log of receipt.logs) {
        if (log.address.toLowerCase() !== usdcAddress.toLowerCase()) continue;
        try {
          const decoded = decodeEventLog({
            abi: transferEventAbi,
            data: log.data,
            topics: log.topics,
          });
          if (
            decoded.eventName === 'Transfer' &&
            (decoded.args as any).to.toLowerCase() === DONATION_WALLET &&
            (decoded.args as any).value >= minUSDCUnits
          ) {
            isUSDCDonation = true;
            break;
          }
        } catch {
          // Not a Transfer event from this log, skip
        }
      }
    }

    if (!isETHDonation && !isUSDCDonation) {
      res.status(400).json({
        error: 'Transaction does not meet donation requirements',
        requirements: {
          wallet: DONATION_WALLET,
          minETH: DONATION_MIN_ETH,
          minUSDC: DONATION_MIN_USDC,
        },
      });
      return;
    }

    const token = isUSDCDonation ? 'USDC' : 'ETH';
    const amount = isUSDCDonation ? DONATION_MIN_USDC : DONATION_MIN_ETH;

    recordDonationBoost(sender, txHash, chainId, token, amount);

    res.json({
      success: true,
      address: sender,
      boost: DONATION_BOOST_POINTS,
      token,
      chainId,
      txHash,
    });
  });

  return router;
}
