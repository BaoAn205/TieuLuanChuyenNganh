# Blockchain Access Audit

Prototype Web Banking mô phỏng để ghi nhận hoạt động truy cập, lưu Audit Event trên Firebase Cloud Firestore và ghi bằng chứng toàn vẹn lên Ethereum local.

## Phạm vi

- Đăng nhập theo các role `ADMIN`, `STAFF`, `AUDITOR`, `CUSTOMER`.
- Mô phỏng xem tài khoản, giao dịch và chuyển tiền nội bộ.
- Ghi Audit Event off-chain; dùng SHA-256 để phát hiện chỉnh sửa.
- Ghi event/hash lên smart contract và xem transaction hash trên Audit Dashboard.
- Không kết nối ngân hàng/thanh toán thật, không dùng cryptocurrency và chưa có AI Agent.

## Công nghệ

| Phần | Công nghệ |
| --- | --- |
| Frontend | HTML, CSS, JavaScript |
| API | FastAPI, Python, Web3.py |
| Database | Firebase Cloud Firestore (SQLite chỉ dùng trong integration tests) |
| Contract | Solidity, Hardhat, Ethers.js (deploy/test tooling) |
| Local chain | Ganache (JSON-RPC `127.0.0.1:8546`) |
| Wallet | MetaMask (EIP-1193 provider) |
| Integrity | SHA-256 |

Hardhat dùng để compile, deploy và test contract; Ganache cung cấp local JSON-RPC node cho demo. Backend gửi transaction bằng Web3.py.

## Chạy demo trên Windows

### 1. Chạy local blockchain

```powershell
cd BlockChain-Access-Audit\blockchain
npm install
npm run node:ganache
```

Giữ terminal này chạy. Ganache in các tài khoản và private key demo để kết nối MetaMask và backend local.

### 2. Deploy contract

Mở terminal mới:

```powershell
cd BlockChain-Access-Audit\blockchain
npm run deploy:local
```

Ghi lại địa chỉ sau `AccessAndAudit deployed to:`. Deployer (account 0) là ADMIN. Gán role bổ sung qua cấu hình `INITIAL_ROLE_ASSIGNMENTS` hoặc tạo customer từ Admin UI.

### 3. Chạy API

Mở terminal mới. Đặt Firebase credential path và project ID; giữ file JSON bên ngoài repository:

```powershell
cd BlockChain-Access-Audit\backend
$env:GOOGLE_APPLICATION_CREDENTIALS = "C:\path\to\firebase-service-account.json"
$env:GOOGLE_CLOUD_PROJECT = "your-firebase-project-id"
py -3.13 -m venv .venv-firestore
.\.venv-firestore\Scripts\python.exe -m pip install -r requirements.txt
$env:BLOCKCHAIN_ENABLED = "true"
$env:BLOCKCHAIN_RPC_URL = "http://127.0.0.1:8546"
$env:BLOCKCHAIN_CONTRACT_ADDRESS = "0xYOUR_DEPLOYED_CONTRACT"
$env:BLOCKCHAIN_PRIVATE_KEY = "0xYOUR_LOCAL_GANACHE_PRIVATE_KEY"
.\.venv-firestore\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Backend dùng Firestore theo mặc định. Các biến môi trường cần được đặt trong cùng cửa sổ PowerShell khởi động API.

### 4. Cấu hình MetaMask và mở giao diện

Thêm mạng MetaMask `Ganache Local`, RPC `http://127.0.0.1:8546`, chain ID `31337`, đơn vị `ETH`. Chỉ dùng private key Ganache cho local demo.

Mở `frontend/index.html` bằng **Open with Live Server**. User, account và wallet được đọc từ Firestore; giao diện không tự điền user ID hoặc tài khoản người nhận. Đăng nhập bằng tài khoản đã provision trong Firebase. Admin có thể tạo customer và account từ form **Create customer** trong Admin workspace. Nếu blockchain bật, backend cấp role `CUSTOMER` cho ví mới bằng signer được cấu hình. Mở `frontend/audit.html` để vào Audit Dashboard. API health check: `http://127.0.0.1:8000/health`.

### 5. Chạy tests

```powershell
cd BlockChain-Access-Audit\blockchain
npm test
cd ..\backend
.\.venv-firestore\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv-firestore\Scripts\python.exe -m pytest tests -q
```

Integration tests dùng SQLite tạm và không kết nối Firestore.

### 6. Demo tamper detection

Chọn event demo trong Audit Dashboard, sau đó chạy lệnh dưới đây trong terminal backend. Lệnh cố ý sửa Firestore mà không cập nhật hash:

```powershell
.\.venv-firestore\Scripts\python.exe tamper_data.py --event-id EVENT_ID --confirm
```

Verify lại event trong dashboard để xem cảnh báo mismatch. Chỉ dùng với dữ liệu demo.

## Tài liệu

- [Kiến trúc hệ thống](docs/architecture.md)
- [API contract](docs/api.md)
- [Smart contract handover](docs/contract.md)
- [Test evidence và demo còn chờ](docs/test-evidence.md)
- [Hướng dẫn backend và Firestore](backend/README.md)
