from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import firebase_admin
from firebase_admin import credentials, db
import hmac
import hashlib
import os
import json

app = FastAPI()

# --- CẤU HÌNH BIẾN MÔI TRƯỜNG ---
ENCRYPT_KEY = os.environ.get("ENCRYPT_KEY", "Gmetrix@2026")
SALT = os.environ.get("SALT", "Gmetrix@2026_SecureSalt!#")
FIREBASE_URL = os.environ.get("FIREBASE_URL")
firebase_cert_json = os.environ.get("FIREBASE_CERT_JSON")

if not firebase_admin._apps:
    try:
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
        db.reference(f"auth/{safe_user}/history/{record_id}").set(payload)
        
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
    
@app.get("/")
async def root():
    return {"message": "Server Backend thi MOS đang hoạt động bình thường! 🚀"}
    
# Khởi động app nội bộ (Render sẽ dùng uvicorn để chạy tự động)
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
