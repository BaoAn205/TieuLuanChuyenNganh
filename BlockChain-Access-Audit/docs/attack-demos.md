# Attack demo scenarios

Các kịch bản dưới đây mô phỏng tấn công có kiểm soát trên ứng dụng local và tài khoản demo. Không dùng với tài khoản hoặc dữ liệu thật. Các lệnh API chỉ gửi request tới `127.0.0.1:8000`.

## Chuẩn bị

1. Khởi động Ganache, contract, backend và frontend theo [README](../README.md#chạy-demo-trên-windows).
2. Đăng nhập bằng `customer-001` và `customer-002` để có hai tài khoản demo. Trong DevTools của trình duyệt đang đăng nhập, mở Console và lấy token bằng:

   ```js
   localStorage.getItem('sessionToken')
   ```

3. Gán token vào biến PowerShell tại terminal demo. Không dán token vào ảnh chụp hoặc nơi công khai:

   ```powershell
   $customer1Token = "DAN_TOKEN_CUSTOMER_001"
   $customer2Token = "DAN_TOKEN_CUSTOMER_002"
   ```

## Attack 1: truy cập không đăng nhập

Mô phỏng gọi API tài khoản khi không có session:

```powershell
try {
  Invoke-WebRequest "http://127.0.0.1:8000/api/accounts/customer-002" -Method Get
} catch {
  [int]$_.Exception.Response.StatusCode
}
```

**Kỳ vọng:** HTTP `401`; response không trả về tài khoản. Nếu nhận `200`, dừng demo và kiểm tra middleware xác thực.

## Attack 2: customer-001 thử đọc tài khoản và audit của customer-002

```powershell
$headers1 = @{ Authorization = "Bearer $customer1Token" }

try {
  Invoke-WebRequest "http://127.0.0.1:8000/api/accounts/customer-002" -Headers $headers1 -Method Get
} catch {
  [int]$_.Exception.Response.StatusCode
}

# Thay EVENT_ID bằng event ID thuộc customer-002 lấy từ Audit Dashboard.
$eventId = "EVENT_ID"
try {
  Invoke-WebRequest "http://127.0.0.1:8000/api/audit/logs/$eventId" -Headers $headers1 -Method Get
} catch {
  [int]$_.Exception.Response.StatusCode
}
```

**Kỳ vọng:** cả hai request bị từ chối với HTTP `403`; customer-001 không đọc được account hoặc event của customer-002.

## Attack 3: customer giả mạo userId để chuyển tiền từ tài khoản khác

Request dưới đây dùng token customer-001 nhưng khai báo `userId` là customer-002. Đích là tài khoản customer-001 để không tạo giao dịch hợp lệ ngay cả khi kiểm soát truy cập bị lỗi. Dùng key mới cho lần thử:

```powershell
$headers1 = @{
  Authorization = "Bearer $customer1Token"
  "Idempotency-Key" = ([guid]::NewGuid().ToString("N"))
}
$body = @{
  userId = "customer-002"
  toAccount = "ACC-1001"
  amount = 1
} | ConvertTo-Json

try {
  Invoke-WebRequest "http://127.0.0.1:8000/api/transactions/transfer" -Headers $headers1 -Method Post -ContentType "application/json" -Body $body
} catch {
  [int]$_.Exception.Response.StatusCode
}
```

**Kỳ vọng:** HTTP `403`; không có giao dịch mới, số dư không đổi. Nếu hệ thống trả `200`, không lặp lại và kiểm tra ngay transaction, balances cùng audit event.

## Attack 4: customer gọi chức năng quản trị

```powershell
$headers1 = @{ Authorization = "Bearer $customer1Token" }
$body = @{
  userId = "attack-demo-user"
  fullName = "Unauthorized Demo"
  password = "DemoOnly123!"
  walletAddress = "0x0000000000000000000000000000000000000001"
  accountId = "ATTACK-DEMO-1"
  initialBalance = 0
} | ConvertTo-Json

try {
  Invoke-WebRequest "http://127.0.0.1:8000/api/admin/customers" -Headers $headers1 -Method Post -ContentType "application/json" -Body $body
} catch {
  [int]$_.Exception.Response.StatusCode
}
```

**Kỳ vọng:** HTTP `403`. User và account giả lập không được tạo trong Firestore. Không chạy request này với token Admin.

## Attack 5: phát lại request chuyển khoản (replay)

Đây là kiểm tra chống gửi lặp khi client mất response. Nó tạo đúng **một giao dịch demo**; dùng số tiền nhỏ và tài khoản demo. Token phải thuộc customer-002, người có `ACC-1002`.

```powershell
$replayKey = [guid]::NewGuid().ToString("N")
$headers2 = @{
  Authorization = "Bearer $customer2Token"
  "Idempotency-Key" = $replayKey
}
$body = @{
  userId = "customer-002"
  toAccount = "ACC-1001"
  amount = 1
} | ConvertTo-Json

$first = Invoke-RestMethod "http://127.0.0.1:8000/api/transactions/transfer" -Headers $headers2 -Method Post -ContentType "application/json" -Body $body
$second = Invoke-RestMethod "http://127.0.0.1:8000/api/transactions/transfer" -Headers $headers2 -Method Post -ContentType "application/json" -Body $body
$first.transaction.transactionId
$second.transaction.transactionId
$second.idempotentReplay
```

**Kỳ vọng:** hai lần trả cùng `transactionId`, lần hai có `idempotentReplay = True`; số dư chỉ thay đổi một lần, chỉ có một transaction tương ứng. Đây là kiểm thử retry an toàn, không phải giao dịch tấn công thành công.

## Attack 6: sửa bằng chứng sau khi giao dịch đã ghi

1. Tạo một giao dịch nhỏ giữa hai tài khoản demo hoặc chọn một event `TRANSFER` hiện có.
2. Trong Firestore, ghi lại giá trị ban đầu trước khi sửa. Sửa **một giá trị duy nhất** trong transaction hoặc `details.balanceSnapshots` của audit event; không sửa `data_hash`/hash tương ứng.
3. Đăng nhập Audit bằng `auditor-001`, tìm đúng event và bấm **Verify**.

**Kỳ vọng:** event bị đánh dấu `MISMATCH` vì nội dung Firestore không còn khớp hash/bằng chứng blockchain hoặc transaction liên kết. Khôi phục chính xác giá trị ban đầu rồi Verify lại; kết quả cần trở về `MATCH` nếu không có trường nào khác bị thay đổi.

Có thể dùng tamper tool hiện có để thay đổi có kiểm soát một audit event:

```powershell
cd ..\backend
.\.venv\Scripts\python.exe .\tamper_data.py --event-id EVENT_ID --confirm
```

Chỉ chạy với event demo. Ghi lại dữ liệu trước khi chạy; không chạy lặp trên cùng event nếu chưa khôi phục.

## Kết thúc demo

- Khôi phục mọi trường Firestore đã sửa.
- Xác nhận các event đã khôi phục Verify ra `MATCH`.
- Đăng xuất các user demo. Không chia sẻ session token hoặc service-account JSON.

Các kịch bản trên minh họa kiểm soát truy cập, tính toàn vẹn và chống replay; chúng không thay thế kiểm thử bảo mật độc lập.
