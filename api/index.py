from fastapi import FastAPI, HTTPException, Response, Header
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
import firebase_admin
from firebase_admin import credentials, db
import hmac
import hashlib
import os
import json
import urllib.request
import urllib.error
import time

app = FastAPI()

# --- CẤU HÌNH BIẾN MÔI TRƯỜNG ---
ENCRYPT_KEY = os.environ.get("ENCRYPT_KEY")
SALT = os.environ.get("SALT")
FIREBASE_URL = os.environ.get("FIREBASE_URL")
firebase_cert_json = os.environ.get("FIREBASE_CERT_JSON")

if not ENCRYPT_KEY or not SALT:
    raise ValueError("LỖI NGHIÊM TRỌNG: Chưa cấu hình biến môi trường ENCRYPT_KEY và SALT trên Server!")
    
if not firebase_admin._apps:
    try:
        if firebase_cert_json:
            cert_dict = json.loads(firebase_cert_json)
            cred = credentials.Certificate(cert_dict)
            firebase_admin.initialize_app(cred, {'databaseURL': FIREBASE_URL})
    except Exception as e:
        print(f"Lỗi khởi tạo Firebase: {e}")

# --- HÀM XÁC THỰC DÙNG CHO CHẤM ĐIỂM ---
def verify_signature(user: str, score: int, max_score: int, client_sig: str) -> bool:
    raw_data = f"{user}|{score}|{max_score}|{SALT}"
    expected_sig = hmac.new(
        key=ENCRYPT_KEY.encode('utf-8'),
        msg=raw_data.encode('utf-8'),
        digestmod=hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected_sig, client_sig)

# --- API 1: NHẬN BÀI THI & GHI KÉP ---
@app.post("/api/submit")
async def submit_exam(payload: dict):
    user = payload.get("user", "")
    score = int(payload.get("score", 0))
    max_score = int(payload.get("max_score", 0))
    client_sig = payload.get("signature", "")
    record_id = payload.get("id", "unknown_id")

    if not verify_signature(user, score, max_score, client_sig):
        raise HTTPException(status_code=403, detail="Chữ ký không hợp lệ!")
    
    try:
        safe_user = hashlib.sha256(user.encode('utf-8')).hexdigest()[:20]
        db.reference(f"submissions/{record_id}").set(payload)
        db.reference(f"user_history/{safe_user}/{record_id}").set(payload)
        return {"status": "success", "message": "Nộp bài thành công!"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Lỗi Server: {str(e)}")

# --- API 2: GHI LỊCH SỬ DÙNG CODE ---
class CodeUsagePayload(BaseModel):
    usage_id: str
    code_hash: str
    user: str
    timestamp: int

@app.post("/api/use-code")
async def record_code_usage(payload: CodeUsagePayload):
    try:
        db.reference(f"code_usages/{payload.usage_id}").set(payload.model_dump())
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# --- API 3: CACHE PROXY CHO HÌNH ẢNH (BẢO VỆ HMAC CHỐNG SPAM) ---
@app.get("/api/image")
async def proxy_image(url: str, t: int = 0, sig: str = ""):
    if not url or not url.startswith("http"):
        raise HTTPException(status_code=400, detail="URL không hợp lệ")

    current_time = int(time.time())
    if current_time - t > 7200 or t > current_time + 60:
        raise HTTPException(status_code=403, detail="Link ảnh đã hết hạn truy cập.")

    raw_sig_data = f"image|{t}|{url}|{SALT}"
    expected_sig = hmac.new(
        key=ENCRYPT_KEY.encode('utf-8'),
        msg=raw_sig_data.encode('utf-8'),
        digestmod=hashlib.sha256
    ).hexdigest()
    
    if not hmac.compare_digest(expected_sig, sig):
        raise HTTPException(status_code=403, detail="Chữ ký không hợp lệ! Truy cập bị từ chối.")
        
    try:
        # Xử lý tự động chuyển đổi link GitHub thành link Raw Public
        if "github.com" in url and "/blob/" in url:
            url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")

        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            img_data = response.read()
            content_type = response.headers.get('Content-Type', 'image/jpeg')

        # Caching ảnh 1 năm trên CDN để giảm tải
        headers = {"Cache-Control": "public, s-maxage=31536000, stale-while-revalidate=86400"}
        return Response(content=img_data, media_type=content_type, headers=headers)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Không thể tải ảnh: {str(e)}")

# --- API 4: CACHE PROXY CHO FILE ZIP LỚN (HỖ TRỢ CHUNKED DOWNLOAD VÀ GITHUB PUBLIC) ---
@app.get("/api/download")
async def proxy_download(url: str, t: int = 0, sig: str = "", range: str = Header(None)):
    """
    Proxy tải file lớn. 
    Tiếp nhận Header Range từ Client truyền xuyên suốt lên GitHub để vượt giới hạn Vercel 4.5MB.
    Dành cho GitHub Public (Không cần Token xác thực).
    """
    if not url or not url.startswith("http"):
        raise HTTPException(status_code=400, detail="URL không hợp lệ")
    
    current_time = int(time.time())
    if current_time - t > 300 or t > current_time + 60:
        raise HTTPException(status_code=403, detail="Link tải đã hết hạn! Chống Spam kích hoạt.")

    raw_sig_data = f"download|{t}|{url}|{SALT}"
    expected_sig = hmac.new(
        key=ENCRYPT_KEY.encode('utf-8'),
        msg=raw_sig_data.encode('utf-8'),
        digestmod=hashlib.sha256
    ).hexdigest()
    
    if not hmac.compare_digest(expected_sig, sig):
        raise HTTPException(status_code=403, detail="Truy cập bị từ chối! Chữ ký không hợp lệ.")

    try:
        # Xử lý chuẩn hóa Link tải GitHub Public
        if "github.com" in url and "/blob/" in url:
            url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
        if "github.com" in url and "/raw/" in url:
            url = url.replace("github.com", "raw.githubusercontent.com").replace("/raw/refs/heads/", "/").replace("/raw/", "/")

        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        
        # CHUYỂN TIẾP LỆNH RANGE: Yêu cầu tải từng khúc (chunk) 4MB để không làm tràn RAM của Vercel
        if range:
            req.add_header("Range", range)
            
        try:
            response = urllib.request.urlopen(req, timeout=30)
        except urllib.error.HTTPError as http_err:
            return Response(content=f"GitHub Error: {http_err.reason}", status_code=http_err.code)

        def iterfile():
            with response:
                while True:
                    chunk = response.read(8192) # Stream 8KB một lần
                    if not chunk: break
                    yield chunk

        # Lưu Cache đề thi lên hệ thống CDN 30 ngày (2592000 giây)
        headers = {
            "Cache-Control": "public, s-maxage=2592000, stale-while-revalidate=86400",
            "Content-Disposition": 'attachment; filename="mos_exam_data.zip"'
        }
        
        # Trả về mã 206 (Partial Content) nếu Client yêu cầu chia nhỏ
        content_range = response.getheader("Content-Range")
        if content_range:
            headers["Content-Range"] = content_range
            headers["Accept-Ranges"] = "bytes"
            
        return StreamingResponse(
            iterfile(), 
            media_type="application/zip", 
            status_code=response.getcode(), 
            headers=headers
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Không thể tải file từ Server gốc: {str(e)}")

@app.get("/")
async def root():
    return {"message": "Server Backend thi MOS đang hoạt động bình thường! 🚀"}
    
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
