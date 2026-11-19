const API = 'http://127.0.0.1:8000';
const $ = (selector) => document.querySelector(selector);

function walletStatus(message, connected = false) {
	$('#auditWalletStatus').textContent = message;
	$('#auditWalletStatus').className = `wallet-status ${connected ? 'connected' : ''}`;
}

function status(message, type = '') {
	$('#status').textContent = message;
	$('#status').className = `status ${type}`;
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
	const data = await response.json();
	if (!response.ok) throw new Error(data.detail || 'Request failed');
	return data;
}

function activeFilters() {
	const query = new URLSearchParams();
	const values = {
		userId: $('#filterUser').value.trim(),
		role: $('#filterRole').value,
		action: $('#filterAction').value,
		blockchainStatus: $('#filterChain').value,
	};
	for (const [key, value] of Object.entries(values)) {
		if (value) query.set(key, value);
	}
	if ($('#filterFrom').value) query.set('from', new Date($('#filterFrom').value).toISOString());
	if ($('#filterTo').value) query.set('to', new Date($('#filterTo').value).toISOString());
	return query.toString();
}

function renderEvents(events) {
	$('#eventCount').textContent = events.length;
	$('#events').innerHTML = events.length ? events.map((event) => `
		<tr>
			<td>#${event.eventId}</td>
			<td>${escapeHtml(event.userId)}</td>
			<td>${escapeHtml(event.role)}</td>
			<td>${escapeHtml(event.action)}</td>
			<td>${escapeHtml(event.resource)}</td>
			<td>${escapeHtml(event.result)}</td>
			<td>${escapeHtml(event.timestamp)}</td>
			<td>${event.blockchainTxHash
				? `<code title="${escapeHtml(event.blockchainTxHash)}">${escapeHtml(event.blockchainTxHash.slice(0, 12))}…</code><small>Block ${event.blockchainBlockNumber} · log ${event.blockchainLogIndex}</small>`
				: 'Off-chain only'}</td>
			<td><button class="verify-button" type="button" data-verify-id="${event.eventId}">Verify</button></td>
			<td><button class="verify-button" type="button" data-detail-id="${event.eventId}">Details</button></td>
		</tr>
	`).join('') : '<tr><td colspan="10">Không có Audit Event phù hợp.</td></tr>';
}

async function loadEvents(userRole) {
	try {
		const role = userRole || $('#auditCurrentUserRole').textContent.trim();
		let data;
		if (role === 'CUSTOMER') {
			data = await callApi('/api/audit/my-logs');
			status(`Đang hiển thị ${data.count ?? data.events.length} sự kiện kiểm toán của riêng bạn (Customer). Bạn có thể bấm Verify để kiểm tra tính toàn vẹn.`, 'success');
		} else {
			const query = activeFilters();
			data = await callApi(`/api/audit/logs${query ? `?${query}` : ''}`);
			status(`${data.count ?? data.events.length} audit event(s) loaded.`, 'success');
		}
		renderEvents(data.events || data.logs || []);
	} catch (error) {
		status(error.message, 'error');
	}
}

function detailFields(event) {
	const rows = [
		['Event ID', event.eventId], ['User', event.userId], ['Role', event.role],
		['Action', event.action], ['Resource', event.resource], ['Timestamp', event.timestamp],
		['Source IP', event.sourceIp], ['Result', event.result], ['Risk level', event.riskLevel],
		['Data hash', event.dataHash], ['Hash version', event.hashVersion],
		['Transaction hash', event.blockchainTxHash || 'Not recorded'],
		['Block number', event.blockchainBlockNumber ?? 'Not recorded'],
		['Log index', event.blockchainLogIndex ?? 'Not recorded'], ['Details', JSON.stringify(event.details)],
	];
	const container = $('#auditDetailFields');
	container.replaceChildren();
	for (const [label, value] of rows) {
		const row = document.createElement('div');
		const term = document.createElement('dt');
		const description = document.createElement('dd');
		term.textContent = label;
		description.textContent = String(value);
		row.append(term, description);
		container.append(row);
	}
	$('#auditDetailDialog').showModal();
}

$('#events').addEventListener('click', async (event) => {
	const verifyButton = event.target.closest('[data-verify-id]');
	const detailButton = event.target.closest('[data-detail-id]');
	if (verifyButton) {
		verifyButton.disabled = true;
		try {
			const result = await callApi('/api/verify-integrity', {
				method: 'POST',
				body: JSON.stringify({ eventId: Number(verifyButton.dataset.verifyId) }),
			});
			verifyButton.textContent = result.verified ? 'MATCH' : 'MISMATCH';
			verifyButton.classList.toggle('verified', result.verified);
			verifyButton.classList.toggle('invalid', !result.verified);
			status(result.message, result.verified ? 'success' : 'error');
		} catch (error) {
			verifyButton.disabled = false;
			status(error.message, 'error');
		}
	}
	if (detailButton) {
		try {
			const result = await callApi(`/api/audit/logs/${detailButton.dataset.detailId}`);
			detailFields(result.event);
		} catch (error) {
			status(error.message, 'error');
		}
	}
});

$('#auditFilters').addEventListener('submit', (event) => {
	event.preventDefault();
	loadEvents();
});
$('#clearFilters').addEventListener('click', () => {
	$('#auditFilters').reset();
	loadEvents();
});
$('#refresh').addEventListener('click', loadEvents);

$('#connectAuditWallet').addEventListener('click', async () => {
	try {
		const address = await window.BancollectWallet.connect();
		walletStatus(`Connected: ${address.slice(0, 6)}…${address.slice(-4)}`, true);
	} catch (error) {
		walletStatus(error.message);
	}
});

window.addEventListener('walletchange', (event) => {
	const address = event.detail.address;
	walletStatus(address ? `Connected: ${address.slice(0, 6)}…${address.slice(-4)}` : 'Wallet disconnected');
});

$('#auditLoginForm').addEventListener('submit', async (event) => {
	event.preventDefault();
	try {
		const walletAddress = window.BancollectWallet.address;
		if (!walletAddress) throw new Error('Connect the assigned Auditor wallet first.');
		const data = await callApi('/api/login', {
			method: 'POST',
			body: JSON.stringify({
				userId: $('#auditUserId').value,
				password: $('#auditPassword').value,
				walletAddress,
			}),
		});
		localStorage.setItem('sessionToken', data.sessionToken);
		walletStatus(`Connected: ${walletAddress.slice(0, 6)}…${walletAddress.slice(-4)}`, true);
		await checkCurrentSession();
	} catch (error) {
		status(error.message, 'error');
	}
});

const handleLogout = async () => {
	try {
		await callApi('/api/logout', { method: 'POST' });
	} catch (e) {
		// Ignore logout error
	} finally {
		localStorage.removeItem('sessionToken');
		walletStatus('Wallet not connected', false);
		await checkCurrentSession();
	}
};

$('#auditLogoutButton').addEventListener('click', handleLogout);
$('#customerLogoutBtn').addEventListener('click', handleLogout);

async function checkCurrentSession() {
	const token = localStorage.getItem('sessionToken');
	if (!token) {
		$('#auditSessionPanel').hidden = true;
		$('#customerBlockedNotice').hidden = true;
		$('#auditLoginForm').hidden = false;
		$('#auditFilters').hidden = true;
		$('#auditWorkspace').hidden = false;
		$('#events').innerHTML = '<tr><td colspan="10">Vui lòng kết nối ví MetaMask và đăng nhập tài khoản Auditor hoặc Admin.</td></tr>';
		$('#eventCount').textContent = '0';
		status('Đăng nhập Auditor hoặc Admin để xem và xác minh logs.', '');
		return;
	}

	try {
		const data = await callApi('/api/me');
		const user = data.user;
		$('#auditCurrentUserName').textContent = user.full_name;
		$('#auditCurrentUserRole').textContent = user.role;
		$('#auditCurrentWallet').textContent = user.walletAddress ? `${user.walletAddress.slice(0, 6)}…${user.walletAddress.slice(-4)}` : '';

		if (user.role === 'CUSTOMER') {
			$('#auditSessionPanel').hidden = false;
			$('#customerBlockedNotice').hidden = false;
			$('#auditLoginForm').hidden = true;
			$('#auditFilters').hidden = true;
			$('#auditWorkspace').hidden = true;
			status('Khu vực giới hạn: Khách hàng (Customer) không có quyền truy cập trang Kiểm toán.', 'error');
			return;
		}

		$('#auditSessionPanel').hidden = false;
		$('#customerBlockedNotice').hidden = true;
		$('#auditLoginForm').hidden = true;
		$('#auditFilters').hidden = false;
		$('#auditWorkspace').hidden = false;

		await loadEvents(user.role);
	} catch (error) {
		localStorage.removeItem('sessionToken');
		$('#auditSessionPanel').hidden = true;
		$('#customerBlockedNotice').hidden = true;
		$('#auditLoginForm').hidden = false;
		$('#auditFilters').hidden = true;
		$('#auditWorkspace').hidden = false;
		$('#events').innerHTML = '<tr><td colspan="10">Phiên làm việc đã hết hạn. Vui lòng đăng nhập lại.</td></tr>';
		$('#eventCount').textContent = '0';
		status(error.message, 'error');
	}
}

checkCurrentSession();
