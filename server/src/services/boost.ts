// In-memory donation boost storage

interface DonationBoost {
  txHash: string;
  chainId: number;
  token: string;
  amount: string;
  timestamp: number;
}

// address.toLowerCase() → boost record
const donationBoosts = new Map<string, DonationBoost>();

// Used tx hashes (prevent double-use)
const usedTxHashes = new Set<string>();

export function getDonationBoost(address: string): number {
  const boost = donationBoosts.get(address.toLowerCase());
  return boost ? 50 : 0;
}

export function recordDonationBoost(
  address: string,
  txHash: string,
  chainId: number,
  token: string,
  amount: string
): void {
  usedTxHashes.add(txHash.toLowerCase());
  donationBoosts.set(address.toLowerCase(), {
    txHash,
    chainId,
    token,
    amount,
    timestamp: Date.now(),
  });
}

export function isTxHashUsed(txHash: string): boolean {
  return usedTxHashes.has(txHash.toLowerCase());
}
