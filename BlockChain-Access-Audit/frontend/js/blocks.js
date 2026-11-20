const BLOCK_API = 'http://127.0.0.1:8000/api/blockchain/blocks';
const blockContainer = document.querySelector('#blocks');
let loadedBlocks = [];

function shortHash(hash) {
  return hash ? `${hash.slice(0, 12)}…${hash.slice(-8)}` : 'Genesis block';
}

function selectBlock(block) {
  document.querySelectorAll('.block-card').forEach((card) => {
    card.classList.toggle('selected', Number(card.dataset.number) === block.number);
  });
  document.querySelector('#selectedTitle').textContent = `Block ${block.number}`;
  document.querySelector('#selectedMeta').textContent =
    `Hash ${block.hash} · Parent ${shortHash(block.parentHash)} · ${new Date(block.timestamp * 1000).toLocaleString()}`;
  const list = document.querySelector('#transactions');
  if (!block.transactions.length) {
    list.innerHTML = '<p class="muted">This block has no transactions.</p>';
    return;
  }
  list.innerHTML = block.transactions.map((tx) => `
    <article class="tx-row">
      <code title="${tx.hash}">${shortHash(tx.hash)}</code>
      <span><small class="muted">FROM</small><br>${tx.from}</span>
      <span><small class="muted">TO</small><br>${tx.to || 'Contract creation'}</span>
      <span>${(Number(tx.valueWei) / 1e18).toLocaleString(undefined, { maximumFractionDigits: 6 })} ETH</span>
    </article>`).join('');
}

async function refreshBlocks() {
  const status = document.querySelector('#chainStatus');
  status.textContent = 'Reading the configured Ganache node…';
  try {
    const token = localStorage.getItem('sessionToken');
    if (!token) throw new Error('Sign in as Admin, Staff, or Auditor to inspect blocks.');
    const response = await fetch(`${BLOCK_API}?limit=20`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || `HTTP ${response.status}`);
    loadedBlocks = data.blocks;
    status.textContent = `Connected · chain ID ${data.chainId} · latest block ${data.latestBlock} · showing ${loadedBlocks.length} blocks`;
    blockContainer.innerHTML = loadedBlocks.map((block) => `
      <button class="block-card" type="button" data-number="${block.number}">
        <span class="eyebrow">BLOCK</span>
        <div class="block-number">#${block.number}</div>
        <div class="block-meta">${block.transactionCount} transaction(s)<br>${new Date(block.timestamp * 1000).toLocaleString()}<br><code title="${block.hash}">${shortHash(block.hash)}</code></div>
      </button>`).join('');
    blockContainer.querySelectorAll('.block-card').forEach((card, index) => {
      card.addEventListener('click', () => selectBlock(loadedBlocks[index]));
    });
    if (loadedBlocks.length) selectBlock(loadedBlocks[loadedBlocks.length - 1]);
  } catch (error) {
    status.textContent = `Could not load blocks: ${error.message}. Check that the backend and configured Ganache node are running.`;
  }
}

document.querySelector('#refreshBlocks').addEventListener('click', refreshBlocks);
refreshBlocks();
