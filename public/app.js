// AgentAuth Demo Application
const API_URL = window.location.origin;

// Demo site API key - auto-registered on first load
let DEMO_API_KEY = localStorage.getItem('agentauth_demo_apikey');

// DOM Elements
const connectState = document.getElementById('connect-state');
const loadingState = document.getElementById('loading-state');
const connectedState = document.getElementById('connected-state');
const errorState = document.getElementById('error-state');
const connectBtn = document.getElementById('connect-btn');
const disconnectBtn = document.getElementById('disconnect-btn');
const retryBtn = document.getElementById('retry-btn');
const errorMessage = document.getElementById('error-message');
const checkBtn = document.getElementById('check-btn');

// Show a specific state
function showState(state) {
  [connectState, loadingState, connectedState, errorState].forEach((el) =>
    el.classList.add('hidden')
  );
  state.classList.remove('hidden');
}

// Register the demo site (or re-register if the server restarted)
async function registerDemoSite() {
  const res = await fetch(`${API_URL}/api/sites/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      domain: window.location.hostname || 'localhost',
      callbackUrls: [window.location.origin],
      minScore: 0, // Demo: allow all scores so we can show the tiers
    }),
  });

  if (!res.ok) throw new Error('Failed to register demo site');

  const data = await res.json();
  DEMO_API_KEY = data.apiKey;
  localStorage.setItem('agentauth_demo_apikey', data.apiKey);
  console.log('Demo site registered:', data.siteId);
  return data.apiKey;
}

async function ensureSiteRegistered() {
  if (!DEMO_API_KEY) return registerDemoSite();

  // Verify the cached key still works (server may have restarted)
  const check = await fetch(`${API_URL}/api/sites/me`, {
    headers: { 'x-api-key': DEMO_API_KEY },
  });

  if (check.ok) return DEMO_API_KEY;

  // Key is stale - re-register
  console.log('Cached API key expired, re-registering...');
  return registerDemoSite();
}

// Update the score display
function updateScoreDisplay(session) {
  // Address
  document.getElementById('session-address').textContent = session.address;
  document.getElementById('session-chain').textContent =
    `${session.sybilDetails?.chainsWithActivity || 0} chains with activity`;

  // Score circle
  const scoreCircle = document.getElementById('score-circle');
  const scoreNumber = document.getElementById('score-number');
  scoreNumber.textContent = session.sybilScore;

  scoreCircle.className = 'score-circle';
  if (session.sybilScore >= 60) scoreCircle.classList.add('score-high');
  else if (session.sybilScore >= 30) scoreCircle.classList.add('score-medium');
  else scoreCircle.classList.add('score-low');

  // Breakdown bars (new: 33/34/33 split)
  const b = session.sybilBreakdown;
  updateBar('balance', b.balanceScore, 33);
  updateBar('txcount', b.txCountScore, 34);
  updateBar('age', b.accountAgeScore, 33);

  // Details
  if (session.sybilDetails) {
    document.getElementById('detail-balance').textContent =
      `${session.sybilDetails.totalBalanceETH.toFixed(4)} ETH`;
    document.getElementById('detail-txcount').textContent =
      session.sybilDetails.totalTransactionCount.toString();
    document.getElementById('detail-chains').textContent =
      `${session.sybilDetails.chainsWithActivity} / ${session.sybilDetails.chainsChecked}`;
  }
  document.getElementById('detail-token').textContent = session.token;

  // Access tiers
  updateTiers(session.sybilScore);
}

function updateBar(name, value, max) {
  const fill = document.getElementById(`bar-${name}`);
  const val = document.getElementById(`val-${name}`);
  fill.style.width = `${(value / max) * 100}%`;
  val.textContent = `${value}/${max}`;
}

function updateTiers(score) {
  const tiers = [
    { id: 'tier-basic', threshold: 0 },
    { id: 'tier-standard', threshold: 25 },
    { id: 'tier-premium', threshold: 50 },
    { id: 'tier-trusted', threshold: 75 },
  ];

  tiers.forEach(({ id, threshold }) => {
    const el = document.getElementById(id);
    if (score >= threshold) {
      el.classList.add('unlocked');
    } else {
      el.classList.remove('unlocked');
    }
  });
}

// Connect and authenticate
async function connect() {
  if (!window.ethereum) {
    showState(errorState);
    errorMessage.textContent =
      'No browser wallet detected. Please install MetaMask or a compatible wallet.';
    return;
  }

  showState(loadingState);

  try {
    // Ensure demo site is registered
    const apiKey = await ensureSiteRegistered();

    // Request accounts
    const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
    const address = accounts[0];

    // Step 1: Get challenge (with API key)
    const challengeRes = await fetch(`${API_URL}/api/challenge`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
      },
      body: JSON.stringify({ address }),
    });

    if (!challengeRes.ok) {
      const err = await challengeRes.json();
      throw new Error(err.error || 'Failed to get challenge from server');
    }

    const challengeData = await challengeRes.json();

    // Step 2: Sign the challenge
    const signature = await window.ethereum.request({
      method: 'personal_sign',
      params: [challengeData.challenge, address],
    });

    // Step 3: Verify and get sybil score (with API key)
    const verifyRes = await fetch(`${API_URL}/api/verify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
      },
      body: JSON.stringify({
        message: challengeData.challenge,
        signature,
      }),
    });

    if (!verifyRes.ok) {
      const err = await verifyRes.json();
      throw new Error(err.error || 'Verification failed');
    }

    const session = await verifyRes.json();

    // Display results
    updateScoreDisplay(session);
    showState(connectedState);
  } catch (err) {
    console.error('Auth error:', err);
    showState(errorState);
    errorMessage.textContent = err.message || 'Authentication failed';
  }
}

// Disconnect
function disconnect() {
  showState(connectState);
}

// Score checker (no API key needed)
async function checkScore() {
  const address = document.getElementById('check-address').value.trim();
  const resultEl = document.getElementById('check-result');

  if (!address || !address.startsWith('0x') || address.length !== 42) {
    resultEl.classList.remove('hidden');
    resultEl.innerHTML = '<pre style="color: var(--danger);">Please enter a valid Ethereum address (0x...)</pre>';
    return;
  }

  resultEl.classList.remove('hidden');
  resultEl.innerHTML = '<div class="spinner" style="margin: 1rem auto;"></div><p style="text-align: center;">Checking across all chains...</p>';

  try {
    const res = await fetch(`${API_URL}/api/score/${address}`);
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Failed to check score');
    }

    const data = await res.json();
    resultEl.innerHTML = `
      <div style="display: flex; align-items: center; gap: 1rem; margin-bottom: 1rem;">
        <div style="font-size: 2rem; font-weight: 700; color: ${data.sybilScore >= 60 ? 'var(--success)' : data.sybilScore >= 30 ? 'var(--warning)' : 'var(--danger)'}">
          ${data.sybilScore}/100
        </div>
        <div>
          <div style="font-size: 0.85rem; color: var(--text-muted);">Sybil Score for</div>
          <code style="font-size: 0.8rem;">${data.address}</code>
        </div>
      </div>
      <pre>${JSON.stringify(data, null, 2)}</pre>
    `;
  } catch (err) {
    resultEl.innerHTML = `<pre style="color: var(--danger);">${err.message}</pre>`;
  }
}

// Event listeners
connectBtn.addEventListener('click', connect);
disconnectBtn.addEventListener('click', disconnect);
retryBtn.addEventListener('click', () => showState(connectState));
checkBtn.addEventListener('click', checkScore);

document.getElementById('check-address').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') checkScore();
});

// Auto-register demo site on load
ensureSiteRegistered().catch((err) => console.warn('Demo site registration deferred:', err.message));
