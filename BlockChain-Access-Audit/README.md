# Blockchain Access Audit

Prototype Web Banking mô phỏng: FastAPI lưu dữ liệu ứng dụng trong PostgreSQL; Ethereum local lưu bằng chứng hash cho các audit event quan trọng.

## Phạm vi

- Đăng nhập theo role `ADMIN`, `STAFF`, `AUDITOR`, `CUSTOMER`.
- Mô phỏng xem tài khoản, giao dịch và chuyển tiền nội bộ.
- Audit event off-chain được lưu PostgreSQL và kiểm tra bằng SHA-256.
- `TRANSFER`, `CHANGE_PROFILE`, `ADMIN_ACCESS` có thể được neo lên smart contract.
- Không kết nối ngân hàng/thanh toán thật.

## Công nghệ

| Phần | Công nghệ |
| --- | --- |
| Frontend | HTML, CSS, JavaScript |
| API | FastAPI, Python, Web3.py |
| Database | PostgreSQL |
| Contract | Solidity, Hardhat, Ethers.js |
| Local chain | Ganache (`127.0.0.1:8546`) |
| Integrity | SHA-256 |

## Chạy trên Windows

### 1. Khởi động blockchain và deploy contract

```powershell
cd BlockChain-Access-Audit\blockchain
npm install
npm run node:ganache
```

Terminal khác:

```powershell
cd BlockChain-Access-Audit\blockchain
npm run deploy:local
```

Ghi lại địa chỉ `AccessAndAudit deployed to:`.

### 2. Tạo PostgreSQL database

Cài PostgreSQL 15+, rồi trong `psql -U postgres` chạy:

```sql
CREATE USER audit_app WITH PASSWORD 'thay-bang-mat-khau-manh';
CREATE DATABASE access_audit OWNER audit_app;
```

### 3. Cài và chạy API

```powershell
cd BlockChain-Access-Audit\backend
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
$env:DATABASE_URL = "postgresql://audit_app:mat-khau-cua-ban@127.0.0.1:5432/access_audit"
$env:BLOCKCHAIN_ENABLED = "true"
$env:BLOCKCHAIN_RPC_URL = "http://127.0.0.1:8546"
$env:BLOCKCHAIN_CONTRACT_ADDRESS = "0xYOUR_DEPLOYED_CONTRACT"
$env:BLOCKCHAIN_PRIVATE_KEY = "0xYOUR_LOCAL_GANACHE_PRIVATE_KEY"
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Backend tạo bảng PostgreSQL tự động. Đặt biến môi trường trong cùng terminal chạy Uvicorn. API health check: `http://127.0.0.1:8000/health`; Swagger: `http://127.0.0.1:8000/docs`.

### 4. Tạo tài khoản ADMIN và mở giao diện

Backend không tạo tài khoản mặc định. Cách tạo hash và thêm admin vào DB nằm trong [hướng dẫn backend](backend/README.md#tạo-tài-khoản-quản-trị-đầu-tiên). Ví admin cần được gán role ADMIN trong contract khi bật blockchain.

Thêm mạng MetaMask `Ganache Local` (RPC `http://127.0.0.1:8546`, chain ID `31337`), rồi mở `frontend/index.html` bằng **Open with Live Server**. Dùng Admin workspace để tạo customer và account. Audit Dashboard ở `frontend/audit.html`.

### 5. Tests và tamper demo

```powershell
cd BlockChain-Access-Audit\blockchain
npm test
cd ..\backend
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest tests -q
```

Integration tests cần PostgreSQL; đặt `POSTGRES_TEST_DATABASE_URL` trỏ tới database test riêng. Fixture sẽ xóa dữ liệu trong database này trước mỗi lượt. Để cố ý sửa audit row trong dữ liệu demo, xem lệnh tamper trong [hướng dẫn backend](backend/README.md#tamper-detection-demo).

## Tài liệu

- [Kiến trúc hệ thống](docs/architecture.md)
- [API contract](docs/api.md)
- [Smart contract handover](docs/contract.md)
- [Test evidence](docs/test-evidence.md)
- [Hướng dẫn backend/PostgreSQL](backend/README.md)
