from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel
import firebase_admin
from firebase_admin import credentials, db
import hmac
import hashlib
import os
import json
import urllib.request

app = FastAPI()

# --- CẤU HÌNH BIẾN MÔI TRƯỜNG ---
ENCRYPT_KEY = os.environ.get("ENCRYPT_KEY", "Gmetrix@2026")
SALT = os.environ.get("SALT", "Gmetrix@2026_SecureSalt!#")
FIREBASE_URL = os.environ.get("FIREBASE_URL")
firebase_cert_json = os.environ.get("FIREBASE_CERT_JSON")

if not firebase_admin._apps:
    try:
        if firebase_cert_json:
            cert_dict = json.loads(firebase_cert_json)
            cred = credentials.Certificate(cert_dict)
            firebase_admin.initialize_app(cred, {'databaseURL': FIREBASE_URL})
    except Exception as e:
        print(f"Lỗi khởi tạo Firebase: {e}")

# --- HÀM XÁC THỰC ---
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
        #payload.pop("signature", None) # Xóa chữ ký trước khi lưu
        
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

# --- API 3: VERCEL EDGE CACHE PROXY CHO HÌNH ẢNH ---
@app.get("/api/image")
async def proxy_image(url: str):
    """
    Biến Vercel thành máy chủ trung gian (CDN Cache).
    Tải ảnh 1 lần từ Github và lưu đệm 1 năm để phục vụ hàng ngàn sinh viên.
    """
    if not url or not url.startswith("http"):
        raise HTTPException(status_code=400, detail="URL không hợp lệ")
        
    try:
        # Hỗ trợ tự động chuyển đổi link github blob sang raw
        if "github.com" in url and "/blob/" in url:
            url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")

        # Khởi tạo Request giả lập trình duyệt để chống bị chặn
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            img_data = response.read()
            content_type = response.headers.get('Content-Type', 'image/jpeg')

        # ĐIỂM CỐT LÕI: Kích hoạt Vercel Edge Cache
        # s-maxage=31536000: Yêu cầu máy chủ CDN của Vercel lưu trữ ảnh này 1 NĂM (không tốn thêm request lên Github)
        headers = {
            "Cache-Control": "public, s-maxage=31536000, stale-while-revalidate=86400"
        }
        
        return Response(content=img_data, media_type=content_type, headers=headers)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Không thể tải ảnh từ Server gốc: {str(e)}")

@app.get("/")
async def root():
    return {"message": "Server Backend thi MOS đang hoạt động bình thường! 🚀"}
    
# Khởi động app nội bộ (Render sẽ dùng uvicorn để chạy tự động)
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
