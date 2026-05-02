// api/download.js
// Cấu hình BẮT BUỘC để kích hoạt Edge Stream trên Vercel (Vượt giới hạn 4.5MB)
export const config = {
  runtime: 'edge',
};

export default async function handler(req) {
  // Lấy các tham số từ URL Client gửi lên
  const { searchParams } = new URL(req.url);
  let targetUrl = searchParams.get('url');
  const t = parseInt(searchParams.get('t') || '0', 10);
  const sig = searchParams.get('sig');

  if (!targetUrl) {
    return new Response('Lỗi: Thiếu tham số URL', { status: 400 });
  }

  // =========================================================
  // 1. BẢO VỆ CHỐNG SPAM (BANDWIDTH EXHAUSTION ATTACK)
  // =========================================================
  const current_time = Math.floor(Date.now() / 1000);
  // Link chỉ sống 5 phút (300 giây). Cho phép sai số đồng hồ 60 giây.
  if (current_time - t > 300 || t > current_time + 60) {
    return new Response('Link tải đã hết hạn! Cảnh báo Spam.', { status: 403 });
  }

  // Lấy KEY từ biến môi trường của Vercel
  const ENCRYPT_KEY = process.env.ENCRYPT_KEY;
  const SALT = process.env.SALT;

  if (!ENCRYPT_KEY || !SALT) {
    return new Response('Lỗi Server: Thiếu cấu hình bảo mật', { status: 500 });
  }

  // =========================================================
  // 2. XÁC THỰC CHỮ KÝ HMAC BẰNG WEB CRYPTO API
  // Phải khớp 100% với hàm generate_signature trong main.py
  // =========================================================
  const rawData = `download|${t}|${targetUrl}|${SALT}`;
  const encoder = new TextEncoder();
  
  try {
    const keyData = encoder.encode(ENCRYPT_KEY);
    const cryptoKey = await crypto.subtle.importKey(
      'raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    
    // Băm chuỗi bằng SHA-256
    const signatureBuffer = await crypto.subtle.sign('HMAC', cryptoKey, encoder.encode(rawData));
    
    // Đổi Buffer sang chuỗi Hexadecimal
    const signatureArray = Array.from(new Uint8Array(signatureBuffer));
    const expectedSig = signatureArray.map(b => b.toString(16).padStart(2, '0')).join('');

    if (sig !== expectedSig) {
      return new Response('Truy cập bị từ chối! Chữ ký không hợp lệ.', { status: 403 });
    }
  } catch (cryptoErr) {
    return new Response('Lỗi tính toán chữ ký điện tử', { status: 500 });
  }

  // =========================================================
  // 3. XỬ LÝ CHUYỂN ĐỔI URL GITHUB & STREAMING EDGE
  // =========================================================
  if (targetUrl.includes('github.com')) {
    targetUrl = targetUrl
        .replace('github.com', 'raw.githubusercontent.com')
        .replace('/blob/', '/')
        .replace('/raw/refs/heads/', '/')
        .replace('/raw/', '/');
  }

  try {
    const response = await fetch(targetUrl, {
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' }
    });

    if (!response.ok) {
      throw new Error(`GitHub trả về mã lỗi: ${response.status}`);
    }

    const headers = new Headers(response.headers);
    // Bật CDN Cache của Vercel trong 30 ngày (Chống Block IP trường học)
    headers.set('Cache-Control', 'public, s-maxage=2592000, stale-while-revalidate=86400');
    headers.set('Content-Disposition', 'attachment; filename="mos_exam_data.zip"');
    headers.delete('content-security-policy');

    // StreamingResponse: Dòng chảy dữ liệu trực tiếp, RAM tiêu thụ gần bằng 0
    return new Response(response.body, { 
      status: response.status, 
      headers: headers 
    });
    
  } catch (err) {
    return new Response(`Lỗi khi Proxy tải file: ${err.message}`, { status: 500 });
  }
}
