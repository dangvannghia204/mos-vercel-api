from fastapi import FastAPI, HTTPException, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
import firebase_admin
from firebase_admin import credentials, db
import hmac
import hashlib
import os
import json
import urllib.request
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
        
        # 1. Ghi vào Hàng đợi (Queue) cho GAS kéo về và xóa
        db.reference(f"submissions/{record_id}").set(payload)
        
        # 2. Ghi vào Lịch sử vĩnh viễn cho Client xem
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

# --- API 3: CACHE PROXY CHO HÌNH ẢNH (ĐÃ CÁCH LY CHỐNG SPAM) ---
@app.get("/api/image")
async def proxy_image(url: str, t: int = 0, sig: str = ""):
    """
    Máy chủ trung gian tải ảnh có bảo vệ bằng chữ ký và thời gian.
    Ngăn chặn làm proxy lậu và chống cạn kiệt băng thông ảnh.
    """
    if not url or not url.startswith("http"):
        raise HTTPException(status_code=400, detail="URL không hợp lệ")

    # 1. BẢO VỆ THỜI GIAN: Link ảnh sống trong 2 tiếng (7200 giây) để sv làm bài thi
    current_time = int(time.time())
    if current_time - t > 7200 or t > current_time + 60:
        raise HTTPException(status_code=403, detail="Link ảnh đã hết hạn truy cập.")

    # 2. KIỂM TRA CHỮ KÝ HMAC
    raw_sig_data = f"image|{t}|{url}|{SALT}"
    expected_sig = hmac.new(
        key=ENCRYPT_KEY.encode('utf-8'),
        msg=raw_sig_data.encode('utf-8'),
        digestmod=hashlib.sha256
    ).hexdigest()
    
    if not hmac.compare_digest(expected_sig, sig):
        raise HTTPException(status_code=403, detail="Chữ ký không hợp lệ! Truy cập bị từ chối.")
        
    # 3. XỬ LÝ CACHE VÀ PHẢN HỒI
    try:
        # Hỗ trợ tự động chuyển đổi link github blob sang raw
        if "github.com" in url and "/blob/" in url:
            url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")

        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            img_data = response.read()
            content_type = response.headers.get('Content-Type', 'image/jpeg')

        headers = {
            "Cache-Control": "public, s-maxage=31536000, stale-while-revalidate=86400"
        }
        
        return Response(content=img_data, media_type=content_type, headers=headers)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Không thể tải ảnh từ Server gốc: {str(e)}")

# --- API 4: CACHE PROXY CHO FILE ZIP LỚN (ĐÃ CÁCH LY CHỐNG SPAM) ---
@app.get("/api/download")
async def proxy_download(url: str, t: int = 0, sig: str = ""):
    """
    Proxy tải file lớn tích hợp chữ ký thời gian (Time-based HMAC).
    Bảo vệ 100GB Băng thông hàng tháng của hệ thống Serverless.
    """
    if not url or not url.startswith("http"):
        raise HTTPException(status_code=400, detail="URL không hợp lệ")
    
    # 1. BẢO VỆ CHỐNG SPAM (REPLAY ATTACK)
    # Giới hạn link chỉ sống tối đa 5 phút (300 giây) kể từ lúc phần mềm tạo ra
    current_time = int(time.time())
    if current_time - t > 300 or t > current_time + 60:
        raise HTTPException(status_code=403, detail="Link tải đã hết hạn! Chống Spam kích hoạt.")

    # 2. XÁC THỰC CHỮ KÝ ĐIỆN TỬ
    raw_sig_data = f"download|{t}|{url}|{SALT}"
    expected_sig = hmac.new(
        key=ENCRYPT_KEY.encode('utf-8'),
        msg=raw_sig_data.encode('utf-8'),
        digestmod=hashlib.sha256
    ).hexdigest()
    
    if not hmac.compare_digest(expected_sig, sig):
        raise HTTPException(status_code=403, detail="Truy cập bị từ chối! Chữ ký không hợp lệ.")

    # 3. STREAM FILE QUA CDN NẾU XÁC THỰC THÀNH CÔNG
    try:
        if "github.com" in url and "/blob/" in url:
            url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
        if "github.com" in url and "/raw/" in url:
            url = url.replace("github.com", "raw.githubusercontent.com").replace("/raw/refs/heads/", "/").replace("/raw/", "/")

        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        response = urllib.request.urlopen(req, timeout=30)

        def iterfile():
            with response:
                while True:
                    chunk = response.read(8192)
                    if not chunk:
                        break
                    yield chunk

        # Lưu Cache đề thi lên Edge Node 30 ngày (2592000 giây)
        headers = {
            "Cache-Control": "public, s-maxage=2592000, stale-while-revalidate=86400",
            "Content-Disposition": 'attachment; filename="mos_exam_data.zip"'
        }
        
        return StreamingResponse(iterfile(), media_type="application/zip", headers=headers)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Không thể tải file từ Server gốc: {str(e)}")

@app.get("/")
async def root():
    return {"message": "Server Backend thi MOS đang hoạt động bình thường! 🚀"}
    
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
