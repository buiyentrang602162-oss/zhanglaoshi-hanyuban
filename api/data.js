// Máy chủ lưu dữ liệu chung cho trang 张老师 · 汉语班
// Chạy trên Vercel (thư mục api/), lưu vào Upstash Redis nối qua tab Storage của Vercel.
const crypto = require('crypto');

function store() {
  const e = process.env;
  let url = e.KV_REST_API_URL || e.UPSTASH_REDIS_REST_URL;
  let tok = e.KV_REST_API_TOKEN || e.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !tok) {
    for (const k of Object.keys(e)) {
      if (/(KV_REST_API_URL|REDIS_REST_URL)$/.test(k) && e[k]) {
        const t = e[k.replace(/URL$/, 'TOKEN')];
        if (t) { url = e[k]; tok = t; break; }
      }
    }
  }
  return url && tok ? { url: url.replace(/\/$/, ''), tok } : null;
}

async function cmd(db, args) {
  const r = await fetch(db.url, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + db.tok, 'Content-Type': 'application/json' },
    body: JSON.stringify(args.map(String)),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || j.error) throw new Error('redis: ' + (j.error || r.status));
  return j.result;
}

const K = { users: 'zl:users', code: 'zl:code', data: 'zl:data', rev: 'zl:rev', lock: 'zl:lock', sess: 'zl:s:' };
const SESSION_SEC = 60 * 60 * 24 * 60; // 60 ngày

function hashPw(pw, salt) {
  return crypto.pbkdf2Sync(String(pw), String(salt), 100000, 32, 'sha256').toString('hex');
}
function safeEq(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
function newCode() { return crypto.randomBytes(4).toString('hex').toUpperCase().slice(0, 6); }
function pub(u) { return { email: u.email, name: u.name, role: u.role }; }

async function session(db, token) {
  if (!token || !/^[a-f0-9]{48}$/.test(token)) return null;
  const em = await cmd(db, ['GET', K.sess + token]);
  if (!em) return null;
  const raw = await cmd(db, ['HGET', K.users, em]);
  return raw ? JSON.parse(raw) : null;
}
async function startSession(db, u) {
  const token = crypto.randomBytes(24).toString('hex');
  await cmd(db, ['SET', K.sess + token, u.email, 'EX', SESSION_SEC]);
  return token;
}
async function readBody(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  if (typeof req.body === 'string') return JSON.parse(req.body || '{}');
  const chunks = [];
  for await (const c of req) chunks.push(c);
  return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
}

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const send = (code, obj) => { res.statusCode = code; res.setHeader('Content-Type', 'application/json; charset=utf-8'); res.end(JSON.stringify(obj)); };
  if (req.method !== 'POST') return send(405, { error: 'method' });
  const db = store();
  if (!db) return send(500, { error: 'nostore' });
  let b;
  try { b = await readBody(req); } catch (e) { return send(400, { error: 'body' }); }
  try {
    const act = b.act;

    if (act === 'status') {
      const n = await cmd(db, ['HLEN', K.users]);
      return send(200, { hasUsers: Number(n) > 0 });
    }

    if (act === 'register') {
      const name = String(b.name || '').trim().slice(0, 80);
      const email = String(b.email || '').trim().toLowerCase().slice(0, 120);
      const pw = String(b.pw || '');
      const role = b.role === 'tg' ? 'tg' : 'gv';
      if (!name || !/^\S+@\S+\.\S+$/.test(email)) return send(400, { error: 'Vui lòng nhập họ tên và email hợp lệ.' });
      if (pw.length < 6) return send(400, { error: 'Mật khẩu cần có ít nhất 6 ký tự.' });
      const n = Number(await cmd(db, ['HLEN', K.users]));
      if (n > 0) {
        const code = await cmd(db, ['GET', K.code]);
        if (!code || String(b.code || '').trim().toUpperCase() !== code) return send(403, { error: 'Mã mời chưa đúng. Hãy hỏi giáo viên đã có tài khoản để lấy mã mời.' });
      }
      const salt = crypto.randomBytes(8).toString('hex');
      const u = { email, name, role, salt, hash: hashPw(pw, salt), at: Date.now() };
      const ok = await cmd(db, ['HSETNX', K.users, email, JSON.stringify(u)]);
      if (!Number(ok)) return send(409, { error: 'Email này đã được đăng ký.' });
      if (n === 0) await cmd(db, ['SET', K.code, newCode()]);
      return send(200, { token: await startSession(db, u), me: pub(u) });
    }

    if (act === 'login') {
      const email = String(b.email || '').trim().toLowerCase();
      const raw = email ? await cmd(db, ['HGET', K.users, email]) : null;
      const u = raw ? JSON.parse(raw) : null;
      if (!u || !safeEq(hashPw(b.pw || '', u.salt), u.hash)) return send(401, { error: 'Email hoặc mật khẩu chưa đúng.' });
      return send(200, { token: await startSession(db, u), me: pub(u) });
    }

    // Từ đây trở xuống cần đăng nhập
    const u = await session(db, b.token);
    if (!u) return send(401, { error: 'auth' });

    if (act === 'logout') { await cmd(db, ['DEL', K.sess + b.token]); return send(200, { ok: true }); }

    if (act === 'get') {
      const [data, rev] = await Promise.all([cmd(db, ['GET', K.data]), cmd(db, ['GET', K.rev])]);
      const out = { me: pub(u), data: data ? JSON.parse(data) : null, rev: Number(rev || 0) };
      if (u.role === 'gv') out.code = await cmd(db, ['GET', K.code]);
      return send(200, out);
    }

    if (act === 'rev') {
      return send(200, { rev: Number((await cmd(db, ['GET', K.rev])) || 0) });
    }

    if (act === 'save') {
      if (!b.data || typeof b.data !== 'object' || !Array.isArray(b.data.students)) return send(400, { error: 'data' });
      const body = JSON.stringify(b.data);
      // khóa ngắn để hai người lưu cùng lúc không ghi đè nhau
      let got = null;
      for (let i = 0; i < 20 && !got; i++) {
        got = await cmd(db, ['SET', K.lock, '1', 'NX', 'PX', '5000']);
        if (!got) await new Promise((r) => setTimeout(r, 150));
      }
      if (!got) return send(503, { error: 'busy' });
      try {
        const cur = Number((await cmd(db, ['GET', K.rev])) || 0);
        if (Number(b.rev) !== cur) {
          const data = await cmd(db, ['GET', K.data]);
          return send(409, { error: 'conflict', rev: cur, data: data ? JSON.parse(data) : null });
        }
        await cmd(db, ['SET', K.data, body]);
        const rev = await cmd(db, ['INCR', K.rev]);
        return send(200, { rev: Number(rev) });
      } finally {
        await cmd(db, ['DEL', K.lock]);
      }
    }

    if (act === 'newcode') {
      if (u.role !== 'gv') return send(403, { error: 'Chỉ giáo viên mới đổi được mã mời.' });
      const code = newCode();
      await cmd(db, ['SET', K.code, code]);
      return send(200, { code });
    }

    return send(400, { error: 'act' });
  } catch (e) {
    return send(500, { error: 'server', detail: String(e.message || e).slice(0, 200) });
  }
};
