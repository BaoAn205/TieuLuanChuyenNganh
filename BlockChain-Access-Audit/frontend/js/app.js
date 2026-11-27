const API = (window.BANCOLLECT_CONFIG?.apiBaseUrl || 'http://127.0.0.1:8000').replace(/\/+$/, '');
const $ = (selector) => document.querySelector(selector);
let currentUser;
let recipient;
let transferPending = false;
let pendingTransferKey = null;
let customerAuditEventsList = [];
let customerAuditCurrentPage = 1;
let customerAuditPageSize = 5;

function showWalletStatus(message, connected = false) {
  $('#walletStatus').textContent = message;
  $('#walletStatus').className = `wallet-status ${connected ? 'connected' : ''}`;
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[character]);
}

async function callApi(path, options = {}) {
  const token = localStorage.getItem('sessionToken');
  const response = await fetch(API + path, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(options.headers || {}),
    },
  });
  const responseText = await response.text();
  let data;
  try {
    data = responseText ? JSON.parse(responseText) : {};
  } catch {
    data = { detail: responseText || `API returned HTTP ${response.status}` };
  }
  if (!response.ok) throw new Error(data.detail || 'Request failed');
  return data;
}

function status(message, type = '', target = '#loginStatus') {
  const element = $(target);
  element.textContent = message;
  element.className = `status ${type}`;
}

async function refresh() {
  const account = await callApi(`/api/accounts/${currentUser.user_id}`);
  const total = Number(account.accounts[0]?.balance || 0);
  $('#balance').textContent = `${total.toLocaleString()} đ`;
  $('#fromAccountDisplay').textContent = account.accounts[0]?.account_id || 'No account';
  $('#availableBalance').textContent = `Available: ${total.toLocaleString()} VND`;

  const transactions = await callApi(`/api/transactions/${currentUser.user_id}`);
  const accountId = account.accounts[0]?.account_id;
  const currentMonth = new Date().toISOString().slice(0, 7);
  const monthTransactions = transactions.transactions.filter((item) => item.created_at?.startsWith(currentMonth));
  const incoming = monthTransactions
    .filter((item) => item.to_account === accountId && item.status === 'SUCCESS')
    .reduce((total, item) => total + Number(item.amount), 0);
  const outgoing = monthTransactions
    .filter((item) => item.from_account === accountId && item.status === 'SUCCESS')
    .reduce((total, item) => total + Number(item.amount), 0);
  $('#incomingTotal').textContent = `₫ ${incoming.toLocaleString()}`;
  $('#outgoingTotal').textContent = `₫ ${outgoing.toLocaleString()}`;
  $('#transactions').innerHTML = transactions.transactions.length
    ? transactions.transactions.map((item, index) => `
        <tr>
          <td>${transactions.transactions.length - index}</td>
          <td>${item.from_account}</td>
          <td>${item.to_account}</td>
          <td>${Number(item.amount).toLocaleString()} đ</td>
          <td>${item.status}</td>
        </tr>
      `).join('')
    : '<tr><td colspan="5">Chưa có giao dịch.</td></tr>';
}

async function lookupRecipient() {
  const accountId = $('#toAccount').value.trim();
  recipient = null;
  $('#recipientPreview').className = 'recipient-preview';

  if (!accountId) {
    $('#recipientPreview').textContent = 'Enter an account number to verify the recipient.';
    return null;
  }

  $('#recipientPreview').textContent = 'Checking account...';
  try {
    recipient = await callApi(`/api/beneficiaries/${encodeURIComponent(accountId)}`);
    $('#recipientPreview').classList.add('verified');
    $('#recipientPreview').textContent = `${recipient.accountName} · ${recipient.bankName}`;
    return recipient;
  } catch (error) {
    $('#recipientPreview').classList.add('invalid');
    $('#recipientPreview').textContent = error.message;
    return null;
  }
}

async function loadAdminLogs() {
  const body = $('#adminEvents');
  try {
    const result = await callApi('/api/audit/logs');
    const logs = result.logs || result.events || [];
    $('#adminEventCount').textContent = logs.length;
    body.innerHTML = logs.length
      ? logs.map((event) => `
          <tr>
            <td>#${event.eventId}</td>
            <td>${escapeHtml(event.userId)}<small>${escapeHtml(event.role)}</small></td>
            <td>${escapeHtml(event.action)}</td>
            <td>${escapeHtml(event.resource)}</td>
            <td>${escapeHtml(event.result)}</td>
            <td>${event.blockchainTxHash ? `<code title="${escapeHtml(event.blockchainTxHash)}">${escapeHtml(event.blockchainTxHash.slice(0, 12))}…</code><small>Block ${escapeHtml(event.blockchainBlockNumber)} · log ${escapeHtml(event.blockchainLogIndex)}</small>` : 'Not recorded'}</td>
            <td><button class="verify-button" type="button" data-event-id="${event.eventId}">Verify</button><button class="verify-button" type="button" data-detail-id="${event.eventId}">Details</button></td>
          </tr>
        `).join('')
      : '<tr><td colspan="7">No audit events recorded.</td></tr>';
    $('#adminStatus').textContent = 'Audit activity loaded.';
    $('#adminStatus').className = 'status success';
    body.querySelectorAll('[data-event-id]').forEach((button) => {
      button.addEventListener('click', () => verifyEvent(button.dataset.eventId, button));
    });
    body.querySelectorAll('[data-detail-id]').forEach((button) => {
      button.addEventListener('click', () => showAuditDetail(button.dataset.detailId));
    });
  } catch (error) {
    $('#adminStatus').textContent = error.message;
    $('#adminStatus').className = 'status error';
  }
}

function renderCustomerAuditTable() {
  const body = $('#customerAuditEvents');
  const total = customerAuditEventsList.length;
  $('#customerAuditCount').textContent = total;

  if (total === 0) {
    body.innerHTML = '<tr><td colspan="6">No audit events yet.</td></tr>';
    $('#customerPaginationSummary').textContent = '0 sự kiện';
    $('#customerCurrentPageDisplay').textContent = 'Trang 1 / 1';
    $('#prevCustomerPage').disabled = true;
    $('#nextCustomerPage').disabled = true;
    return;
  }

  const totalPages = Math.ceil(total / customerAuditPageSize) || 1;
  if (customerAuditCurrentPage > totalPages) customerAuditCurrentPage = totalPages;
  if (customerAuditCurrentPage < 1) customerAuditCurrentPage = 1;

  const startIdx = (customerAuditCurrentPage - 1) * customerAuditPageSize;
  const endIdx = Math.min(startIdx + customerAuditPageSize, total);
  const pageItems = customerAuditEventsList.slice(startIdx, endIdx);

  body.innerHTML = pageItems.map((event) => `
    <tr>
      <td>#${event.eventId}</td>
      <td>${escapeHtml(event.action)}</td>
      <td>${escapeHtml(event.resource)}</td>
      <td>${escapeHtml(event.timestamp)}</td>
      <td>${event.blockchainTxHash ? 'On-chain' : 'Off-chain'}</td>
      <td><button class="verify-button" type="button" data-detail-id="${event.eventId}">Details</button></td>
    </tr>
  `).join('');

  $('#customerPaginationSummary').textContent = `${startIdx + 1} - ${endIdx} trong ${total}`;
  $('#customerCurrentPageDisplay').textContent = `Trang ${customerAuditCurrentPage} / ${totalPages}`;
  $('#prevCustomerPage').disabled = (customerAuditCurrentPage <= 1);
  $('#nextCustomerPage').disabled = (customerAuditCurrentPage >= totalPages);
}

async function loadCustomerAudit() {
  try {
    const result = await callApi('/api/audit/my-logs');
    customerAuditEventsList = result.events || [];
    renderCustomerAuditTable();
    $('#customerAuditStatus').textContent = 'Only events belonging to your user are shown.';
    $('#customerAuditStatus').className = 'status success';
  } catch (error) {
    $('#customerAuditStatus').textContent = error.message;
    $('#customerAuditStatus').className = 'status error';
  }
}

async function showAuditDetail(eventId) {
  try {
    const result = await callApi(`/api/audit/logs/${eventId}`);
    const event = result.event;
    const fields = [
      ['Event ID', event.eventId], ['User', event.userId], ['Role', event.role],
      ['Action', event.action], ['Resource', event.resource], ['Timestamp', event.timestamp],
      ['Source IP', event.sourceIp], ['Result', event.result], ['Risk', event.riskLevel],
      ['SHA-256', event.dataHash], ['Blockchain transaction', event.blockchainTxHash || 'Not recorded'],
      ['Block number', event.blockchainBlockNumber ?? 'Not recorded'],
      ['Log index', event.blockchainLogIndex ?? 'Not recorded'],
      ['Details', JSON.stringify(event.details)],
    ];
    const container = $('#eventDetailFields');
    container.replaceChildren();
    for (const [label, value] of fields) {
      const row = document.createElement('div');
      const term = document.createElement('dt');
      const description = document.createElement('dd');
      term.textContent = label;
      description.textContent = String(value);
      row.append(term, description);
      container.append(row);
    }
    $('#eventDetailDialog').showModal();
  } catch (error) {
    status(error.message, 'error', currentUser.role === 'CUSTOMER' ? '#customerAuditStatus' : '#adminStatus');
  }
}

async function activateSession(user, walletAddress) {
  currentUser = user;
  $('#loginPanel').hidden = true;
  $('#logoutButton').hidden = false;

  if (currentUser.role === 'ADMIN') {
    $('#customerNav').hidden = true;
    $('#adminNav').hidden = false;
    $('#appPanel').hidden = true;
    $('#adminPanel').hidden = false;
    $('#adminName').textContent = currentUser.full_name;
    $('#greetingKicker').textContent = 'Administrator workspace';
    $('#pageTitle').textContent = 'Audit operations';
    await loadAdminLogs();
  } else {
    $('#adminNav').hidden = true;
    $('#customerNav').hidden = false;
    $('#adminPanel').hidden = true;
    $('#appPanel').hidden = false;
    $('#quickTransfer').hidden = false;
    $('#editProfileButton').hidden = false;
    showWalletStatus(`Connected: ${walletAddress.slice(0, 6)}…${walletAddress.slice(-4)}`, true);
    $('#userName').textContent = currentUser.full_name;
    $('#greetingKicker').textContent = `Welcome back, ${currentUser.full_name}`;
    $('#pageTitle').textContent = 'Banking overview';
    await refresh();
    await lookupRecipient();
    await loadCustomerAudit();
  }
}

async function verifyEvent(eventId, button) {
  button.disabled = true;
  button.textContent = 'Checking...';
  try {
    const result = await callApi('/api/verify-integrity', {
      method: 'POST',
      body: JSON.stringify({ eventId: Number(eventId) }),
    });
    button.textContent = result.verified ? 'Match' : 'Mismatch';
    button.className = `verify-button ${result.verified ? 'verified' : 'invalid'}`;
    $('#adminStatus').textContent = result.message;
    $('#adminStatus').className = `status ${result.verified ? 'success' : 'error'}`;
  } catch (error) {
    button.disabled = false;
    button.textContent = 'Retry';
    $('#adminStatus').textContent = error.message;
    $('#adminStatus').className = 'status error';
  }
}

document.querySelectorAll('.role-option').forEach((button) => {
  button.addEventListener('click', () => {
    document.querySelectorAll('.role-option').forEach((option) => option.classList.remove('active'));
    button.classList.add('active');
    $('#loginRole').value = button.dataset.role;
    $('#userId').value = '';
    $('#password').value = '';
    $('#loginHint').textContent = button.dataset.role === 'ADMIN'
      ? 'Enter the administrator user ID associated with the connected wallet.'
      : 'Enter the customer user ID associated with the connected wallet.';
    $('#password').focus();
  });
});

$('#connectWallet').addEventListener('click', async () => {
  try {
    const address = await window.BancollectWallet.connect();
    showWalletStatus(`Connected: ${address.slice(0, 6)}…${address.slice(-4)}`, true);
  } catch (error) {
    showWalletStatus(error.message);
  }
});

window.addEventListener('walletchange', (event) => {
  const address = event.detail.address;
  showWalletStatus(address ? `Connected: ${address.slice(0, 6)}…${address.slice(-4)}` : 'Wallet disconnected');
});

$('#loginForm').addEventListener('submit', async (event) => {
  event.preventDefault();

  try {
    const walletAddress = window.BancollectWallet.address;
    if (!walletAddress) throw new Error('Connect the assigned MetaMask wallet first.');
    const data = await callApi('/api/login', {
      method: 'POST',
      body: JSON.stringify({
        userId: $('#userId').value,
        password: $('#password').value,
        walletAddress,
      }),
    });

    if (data.user.role !== $('#loginRole').value) {
      throw new Error('This account does not match the selected access type.');
    }

    localStorage.setItem('sessionToken', data.sessionToken);
    await activateSession(data.user, walletAddress);
    if (data.user.role === 'ADMIN') await callApi('/api/admin/access', { method: 'POST' });
    status('Signed in successfully.', 'success');
  } catch (error) {
    status(error.message, 'error');
  }
});

$('#toAccount').addEventListener('blur', lookupRecipient);
$('#toAccount').addEventListener('change', lookupRecipient);

$('#transferForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  const verifiedRecipient = await lookupRecipient();
  if (!verifiedRecipient) return;

  const amount = Number($('#amount').value);
  const available = Number($('#availableBalance').textContent.replace(/[^\d]/g, ''));
  if (!Number.isFinite(amount) || amount < 1000) {
    status('Minimum transfer amount is 1,000 VND.', 'error', '#appStatus');
    return;
  }
  if (amount > available) {
    status('Insufficient available balance.', 'error', '#appStatus');
    return;
  }
  if (verifiedRecipient.accountId === $('#fromAccountDisplay').textContent) {
    status('Source and recipient accounts must be different.', 'error', '#appStatus');
    return;
  }

  $('#confirmRecipient').textContent = verifiedRecipient.accountName;
  $('#confirmAccount').textContent = `${verifiedRecipient.accountId} · ${verifiedRecipient.bankName}`;
  $('#confirmSource').textContent = $('#fromAccountDisplay').textContent;
  $('#confirmAmount').textContent = `${amount.toLocaleString()} VND`;
  $('#confirmStatus').textContent = '';
  $('#confirmTransfer').disabled = false;
  $('#confirmTransfer').textContent = 'Confirm and send';
  const requestFingerprint = JSON.stringify([
    currentUser.user_id,
    $('#fromAccountDisplay').textContent,
    $('#toAccount').value.trim(),
    amount,
  ]);
  const storageKey = `transfer-idempotency:${currentUser.user_id}`;
  let savedRequest;
  try {
    savedRequest = JSON.parse(sessionStorage.getItem(storageKey) || 'null');
  } catch {
    savedRequest = null;
  }
  if (savedRequest?.fingerprint === requestFingerprint && savedRequest.key) {
    pendingTransferKey = savedRequest.key;
  } else {
    const randomKey = new Uint8Array(16);
    globalThis.crypto.getRandomValues(randomKey);
    pendingTransferKey = Array.from(randomKey, (value) => value.toString(16).padStart(2, '0')).join('');
    sessionStorage.setItem(storageKey, JSON.stringify({ fingerprint: requestFingerprint, key: pendingTransferKey }));
  }
  $('#transferConfirmDialog').showModal();
});

$('#transferConfirmDialog').addEventListener('cancel', (event) => {
  if (transferPending) event.preventDefault();
});

$('#transferConfirmDialog').addEventListener('close', () => {
  if (!transferPending) pendingTransferKey = null;
});

$('#confirmTransfer').addEventListener('click', async () => {
  if (transferPending) return;
  transferPending = true;
  $('#confirmTransfer').disabled = true;
  $('#confirmTransfer').textContent = 'Processing...';
  try {
    const data = await callApi('/api/transactions/transfer', {
      method: 'POST',
      headers: { 'Idempotency-Key': pendingTransferKey },
      body: JSON.stringify({
        userId: currentUser.user_id,
        toAccount: $('#toAccount').value,
        amount: Number($('#amount').value),
      }),
    });

    await refresh();
    $('#transferConfirmDialog').close();
    pendingTransferKey = null;
    sessionStorage.removeItem(`transfer-idempotency:${currentUser.user_id}`);
    $('#transferForm').reset();
    $('#toAccount').value = '';
    recipient = null;
    $('#recipientPreview').textContent = 'Enter an account number to verify the recipient.';
    status('Transfer completed successfully.', 'success', '#appStatus');
  } catch (error) {
    $('#confirmStatus').textContent = error.message;
    $('#confirmStatus').className = 'status error';
    $('#confirmTransfer').disabled = false;
    $('#confirmTransfer').textContent = 'Try again';
  } finally {
    transferPending = false;
  }
});

$('#refreshAdminLogs').addEventListener('click', loadAdminLogs);

$('#createCustomerForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const button = form.querySelector('button[type="submit"]');
  const output = $('#createCustomerStatus');
  button.disabled = true;
  output.textContent = 'Creating customer...';
  output.className = 'status';
  try {
    const result = await callApi('/api/admin/customers', {
      method: 'POST',
      body: JSON.stringify({
        userId: $('#newCustomerUserId').value.trim(),
        fullName: $('#newCustomerName').value.trim(),
        password: $('#newCustomerPassword').value,
        walletAddress: $('#newCustomerWallet').value.trim(),
        accountId: $('#newCustomerAccount').value.trim(),
        initialBalance: Number($('#newCustomerBalance').value),
      }),
    });
    output.textContent = `Created ${result.user.user_id} with account ${result.account.account_id}.`;
    output.className = 'status success';
    form.reset();
    $('#newCustomerBalance').value = '0';
  } catch (error) {
    output.textContent = error.message;
    output.className = 'status error';
  } finally {
    button.disabled = false;
  }
});

$('#refreshCustomerAudit').addEventListener('click', loadCustomerAudit);

$('#toggleCustomerAudit')?.addEventListener('click', () => {
  const content = $('#customerAuditContent');
  const btn = $('#toggleCustomerAudit');
  const isCollapsed = content.hidden;
  content.hidden = !isCollapsed;
  btn.textContent = isCollapsed ? 'Thu gọn ▲' : 'Mở rộng ▼';
  btn.setAttribute('aria-expanded', isCollapsed ? 'true' : 'false');
});

$('#customerPageSize')?.addEventListener('change', (e) => {
  customerAuditPageSize = Number(e.target.value) || 5;
  customerAuditCurrentPage = 1;
  renderCustomerAuditTable();
});

$('#prevCustomerPage')?.addEventListener('click', () => {
  if (customerAuditCurrentPage > 1) {
    customerAuditCurrentPage--;
    renderCustomerAuditTable();
  }
});

$('#nextCustomerPage')?.addEventListener('click', () => {
  const totalPages = Math.ceil(customerAuditEventsList.length / customerAuditPageSize) || 1;
  if (customerAuditCurrentPage < totalPages) {
    customerAuditCurrentPage++;
    renderCustomerAuditTable();
  }
});
$('#quickTransfer').addEventListener('click', () => {
  $('#transfer').scrollIntoView({ behavior: 'smooth', block: 'center' });
  $('#toAccount').focus({ preventScroll: true });
});
$('#editProfileButton').addEventListener('click', () => {
  $('#profileName').value = currentUser.full_name;
  $('#profileStatus').textContent = '';
  $('#profileDialog').showModal();
});

$('#customerAuditEvents').addEventListener('click', (event) => {
  const button = event.target.closest('[data-detail-id]');
  if (button) showAuditDetail(button.dataset.detailId);
});

$('#cancelProfile').addEventListener('click', () => $('#profileDialog').close());

$('#profileForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    const result = await callApi('/api/profile', {
      method: 'PATCH',
      body: JSON.stringify({ fullName: $('#profileName').value }),
    });
    currentUser = result.user;
    $('#userName').textContent = currentUser.full_name;
    $('#greetingKicker').textContent = `Welcome back, ${currentUser.full_name}`;
    $('#profileDialog').close();
    status('Profile updated and recorded in the audit ledger.', 'success', '#appStatus');
  } catch (error) {
    $('#profileStatus').textContent = error.message;
    $('#profileStatus').className = 'status error';
  }
});

$('#logoutButton').addEventListener('click', async () => {
  try {
    await callApi('/api/logout', { method: 'POST' });
  } catch (error) {
    status(error.message, 'error');
  } finally {
    localStorage.removeItem('sessionToken');
    currentUser = null;
    $('#loginForm').reset();
    $('#loginPanel').hidden = false;
    $('#appPanel').hidden = true;
    $('#adminPanel').hidden = true;
    $('#customerNav').hidden = true;
    $('#adminNav').hidden = true;
    $('#quickTransfer').hidden = true;
    $('#editProfileButton').hidden = true;
    $('#logoutButton').hidden = true;
    $('#greetingKicker').textContent = 'Secure digital banking';
    $('#pageTitle').textContent = 'Sign in to Bancollect';
  }
});

async function restoreSession() {
  if (!localStorage.getItem('sessionToken')) return;
  try {
    const data = await callApi('/api/me');
    await activateSession(data.user, data.user.walletAddress);
    status('Session restored.', 'success');
  } catch (error) {
    localStorage.removeItem('sessionToken');
    status(error.message, 'error');
  }
}

restoreSession();
