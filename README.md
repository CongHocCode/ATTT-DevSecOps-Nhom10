# ĐỒ ÁN AN TOÀN THÔNG TIN - HK1 (2026 - 2027)
## ĐỀ TÀI 10: TÍCH HỢP KIỂM SOÁT AN TOÀN VÀO VÒNG ĐỜI PHÁT TRIỂN ỨNG DỤNG WEB (DEVSECOPS)

* **Nhóm thực hiện:** Nhóm 10

---
*Kho lưu trữ mã nguồn và dây chuyền kiểm thử bảo mật tự động CI/CD.*

## Build và kiểm tra Docker image

Dockerfile sử dụng hai giai đoạn. Giai đoạn `dependencies` cài công cụ biên dịch cần cho `sqlite3` và chỉ cài các dependency production. Giai đoạn `runtime` chỉ nhận `node_modules` production cùng `package.json`, `server.js`, và chạy bằng user `appuser`. File `.dockerignore` loại `node_modules` của máy host khỏi build context để tránh ghi đè module native được cài trong Linux container.

Build image và chạy unit test:

```powershell
npm ci
npm test
docker build -t app-devsecops:docker-opt .
```

Xác nhận image chạy bằng user không phải root:

```powershell
docker run --rm --entrypoint id app-devsecops:docker-opt
```

Kết quả phải hiện user `appuser` (UID khác `0`). Chạy ứng dụng và kiểm tra endpoint:

```powershell
docker run --rm -d --name devsecops-check -p 3000:3000 app-devsecops:docker-opt
Invoke-RestMethod http://localhost:3000/
docker stop devsecops-check
```

Endpoint trả về JSON có `status: "OK"`. Có thể xem kích thước image trước và sau tối ưu bằng `docker image ls app-devsecops`.
