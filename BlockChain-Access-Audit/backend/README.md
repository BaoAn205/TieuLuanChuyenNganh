# Backend và PostgreSQL

Backend FastAPI chỉ dùng PostgreSQL cho users, sessions, accounts, transactions và audit_events. Blockchain local vẫn giữ vai trò neo hash audit quan trọng.

## Dùng PostgreSQL trên Render với pgAdmin

### Tạo database trên Render

Ở trang **New Postgres** như ảnh:

1. **Name:** `tln` dùng được; đây chỉ là tên service trong dashboard.
2. **Project:** để trống nếu chưa tạo Render Project.
3. **Database:** nên nhập `access_audit`. **User:** nên nhập `audit_app` nếu các trường này đang cho phép nhập. Render tạo hai giá trị này khi để trống, và không đổi được dbname/username sau khi tạo.
4. **Region:** chọn vùng gần bạn nhất hiện có; nếu sau này deploy API lên Render, đặt API cùng region với database.
5. **PostgreSQL Version:** để mặc định.
6. **Plan:** ảnh đang hiển thị `$0/month`; dùng được cho demo. Free Postgres hiện bị giới hạn 1 GB, không có backup và hết hạn sau 30 ngày. Nâng plan nếu cần giữ dữ liệu lâu dài.
7. Giữ storage mặc định phù hợp với plan rồi nhấn **Create database**. Chờ trạng thái chuyển thành **Available**.

### Lấy URL kết nối

Trong trang database Render, mở **Connect** và sao chép **External Database URL**. Dùng external URL vì API trên máy tính của bạn và pgAdmin bên ngoài Render đều cần kết nối qua internet. Không dùng Internal URL ở môi trường này; URL đó dành cho service chạy cùng region bên trong Render. External connections yêu cầu TLS; thêm `sslmode=require` vào URL nếu chưa có.

URL thường có dạng:

```text
postgresql://USER:PASSWORD@HOST/DBNAME?sslmode=require
```

Giữ URL/mật khẩu riêng tư, không gửi vào chat hoặc commit vào Git.

### Nối pgAdmin 4

1. Mở pgAdmin, nhấn phải **Servers** → **Register** → **Server**.
2. Tab **General**: đặt tên như `Render tln`.
3. Tab **Connection**: điền **Host name/address**, **Port** (`5432`), **Maintenance database** (dbname ở cuối URL), **Username** và **Password** theo External Database URL.
4. Tab **SSL**: đặt **SSL mode** thành `require`.
5. Nhấn **Save**. Nếu kết nối thất bại, kiểm tra URL External, trạng thái database là **Available**, và mục **Networking / IP allow list** có cho phép IP hiện tại của bạn.

### Nối FastAPI local vào Render

Trong PowerShell chạy backend, đặt toàn bộ External Database URL vào biến môi trường; giữ nguyên giá trị thực Render cấp và bảo đảm có `sslmode=require`:

```powershell
$env:DATABASE_URL = "postgresql://USER:PASSWORD@HOST/DBNAME?sslmode=require"
```

Sau đó từ thư mục `BlockChain-Access-Audit\backend` khởi động API:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Backend tự tạo các bảng khi khởi động. Trong pgAdmin, mở database rồi **Refresh → Schemas → public → Tables**. Nếu mật khẩu có ký tự đặc biệt trong URL, URL-encode mật khẩu hoặc đặt mật khẩu gồm chữ/số/ký tự an toàn URL trong phần cấu hình Render.

## Cài đặt trên Windows

1. Cài PostgreSQL và đảm bảo service đang chạy. Mở SQL Shell (psql) hoặc pgAdmin, tạo database và user riêng:

```sql
CREATE USER audit_app WITH PASSWORD 'thay-bang-mat-khau-manh';
CREATE DATABASE access_audit OWNER audit_app;
```

2. Trong PowerShell, tại thư mục `backend`, tạo môi trường Python và cài dependencies:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

3. Cấu hình kết nối PostgreSQL trong cùng PowerShell session:

```powershell
$env:DATABASE_URL = "postgresql://audit_app:mat-khau-cua-ban@127.0.0.1:5432/access_audit"
```

Nếu mật khẩu có ký tự đặc biệt như `@`, `:`, `/`, cần URL-encode phần mật khẩu. Khi API khởi động lần đầu, nó tự tạo bảng và cột còn thiếu.

4. Khởi động API:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Kiểm tra `http://127.0.0.1:8000/health` và tài liệu API tại `http://127.0.0.1:8000/docs`.

## Chạy demo blockchain

Trong một terminal khác, chạy Ganache, deploy hợp đồng theo hướng dẫn ở README dự án; sau đó cấu hình các biến sau trước khi chạy API:

```powershell
$env:BLOCKCHAIN_ENABLED = "true"
$env:BLOCKCHAIN_RPC_URL = "http://127.0.0.1:8546"
$env:BLOCKCHAIN_CONTRACT_ADDRESS = "0xDIA-CHI-CONTRACT"
$env:BLOCKCHAIN_PRIVATE_KEY = "0xPRIVATE-KEY-GANACHE-LOCAL"
```

Chỉ dùng private key của Ganache local. `DATABASE_URL` và các biến blockchain phải được đặt trong terminal chạy Uvicorn.

## Tạo tài khoản quản trị đầu tiên

Backend không tự tạo tài khoản mặc định. Tạo hash mật khẩu bằng hàm `hash_password` trong Python, sau đó thêm user bằng psql. Ví dụ tạo hash:

```powershell
@'
from app.main import hash_password
print(hash_password("doi-mat-khau-nay"))
'@ | .\.venv\Scripts\python.exe -
```

Thêm user, thay ví bằng địa chỉ đã được gán role ADMIN trên contract nếu bật blockchain:

```sql
INSERT INTO users (user_id, full_name, role, password, wallet_address)
VALUES ('admin-001', 'System Administrator', 'ADMIN', '<PBKDF2_HASH>', '0x...');
```

Có thể tạo tài khoản cho khách hàng sau khi đăng nhập Admin workspace.

## PostgreSQL data

Render PostgreSQL l? database duy nh?t c?a ?ng d?ng. Backend t? t?o schema khi kh?i ??ng; d? li?u ng??i d?ng v? ?ng d?ng ???c qu?n l? trong database n?y.

## Tamper detection demo

Chỉ dùng với dữ liệu demo: chọn event ID trong Audit Dashboard rồi chạy:

```powershell
$env:DATABASE_URL = "postgresql://audit_app:mat-khau-cua-ban@127.0.0.1:5432/access_audit"
.\.venv\Scripts\python.exe .\tamper_data.py --event-id EVENT_ID --confirm
```

Lệnh sửa `resource` mà giữ nguyên `data_hash`; verify lại event trong dashboard để thấy mismatch.
