# Blockchain Access Audit

Prototype Web Banking mô phỏng để ghi nhận hoạt động truy cập, lưu Audit Event trên SQLite và ghi bằng chứng toàn vẹn lên Ethereum local.

## Phạm vi Phase 1

- Đăng nhập theo các role `ADMIN`, `STAFF`, `AUDITOR`, `CUSTOMER`.
- Mô phỏng xem tài khoản, xem giao dịch và chuyển tiền nội bộ.
- Ghi Audit Event off-chain; dùng SHA-256 để phát hiện chỉnh sửa.
- Ghi event/hash lên smart contract và xem transaction hash trên Audit Dashboard.
- Không kết nối ngân hàng/thanh toán thật, không dùng cryptocurrency và chưa có AI Agent.

## Công nghệ hiện tại

| Phần | Công nghệ |
| --- | --- |
| Frontend | HTML, CSS, JavaScript |
| API | FastAPI, Python, Web3.py |
| Database | SQLite |
| Contract | Solidity, Hardhat, Ethers.js (deploy/test tooling) |
| Local chain | Ganache (JSON-RPC `127.0.0.1:8546`) |
| Wallet | MetaMask (EIP-1193 provider) |
| Integrity | SHA-256 |

Hardhat dùng để compile, deploy và test contract; Ganache cung cấp local JSON-RPC node cho demo. Ethers.js được dùng trong Hardhat deploy/test tooling, còn backend gửi transaction bằng Web3.py.

## Chạy demo trên Windows

### 1. Cài và chạy local blockchain

```powershell
cd BlockChain-Access-Audit\blockchain
npm install
npm run node:ganache
```

Giữ terminal này chạy. Ganache dùng mnemonic demo cố định, in ra các account/private key để kết nối MetaMask và backend local.

### 2. Deploy contract

Mở terminal mới:

```powershell
cd BlockChain-Access-Audit\blockchain
npm run deploy:local
```

Ghi lại địa chỉ được in sau `AccessAndAudit deployed to:`.

Script deploy local cũng gán role cho account Hardhat: account 0 ADMIN, account 1 STAFF, account 2 AUDITOR, account 3 CUSTOMER.

### 3. Chạy API

Mở terminal mới:

```powershell
cd BlockChain-Access-Audit\backend
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
$env:BLOCKCHAIN_ENABLED = "true"
$env:BLOCKCHAIN_RPC_URL = "http://127.0.0.1:8546"
$env:BLOCKCHAIN_CONTRACT_ADDRESS = "0xYOUR_DEPLOYED_CONTRACT"
$env:BLOCKCHAIN_PRIVATE_KEY = "0xYOUR_LOCAL_GANACHE_PRIVATE_KEY"
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Nếu vừa cài virtualenv trong bước trên, có thể dùng `requirements-dev.txt` để cài thêm pytest/httpx khi muốn chạy test:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
```

### 4. Cấu hình MetaMask và mở giao diện

Thêm mạng MetaMask tên `Ganache Local`, RPC `http://127.0.0.1:8546`, chain ID `31337`, tiền tệ `ETH`. Import account 0-3 bằng private key chỉ dành cho development được in trong terminal Ganache. Không dùng các khóa đó ngoài local demo.

Trong VS Code, mở `frontend/index.html`, chọn **Open with Live Server**. Bấm **Connect MetaMask**, chọn đúng ví theo role rồi đăng nhập. Mở `frontend/audit.html` và dùng account 2 để đăng nhập Auditor. API health check: `http://127.0.0.1:8000/health`.

Demo users:

| Role | User ID | Password |
| --- | --- | --- |
| Customer | `customer-001` | `customer123` |
| Admin | `admin-001` | `admin123` |
| Auditor | `auditor-001` | `audit123` |
| Staff | `staff-001` | `staff123` |

Đăng nhập yêu cầu cả password và MetaMask wallet đã được gán đúng role trên contract.

Recipient demo account: `ACC-2002`.

### 5. Chạy test

```powershell
cd BlockChain-Access-Audit\blockchain
npm test
cd ..\backend
.\.venv\Scripts\python.exe -m pytest tests -q
```

### 6. Demo tamper detection

Đăng nhập, tạo hoặc chọn event đã ghi on-chain. Trong terminal khác, sửa một event SQLite:

```powershell
cd BlockChain-Access-Audit\backend
.\.venv\Scripts\python.exe tamper_data.py --event-id EVENT_ID --confirm
```

Quay lại Audit Dashboard và verify event đó. Nếu field được hash bị sửa, dashboard báo mismatch. Chỉ chạy script trên database demo.

## Tài liệu

- [Kiến trúc hệ thống](docs/architecture.md)
- [API contract](docs/api.md)
- [Smart contract handover](docs/contract.md)
- [Test evidence và demo còn chờ](docs/test-evidence.md)