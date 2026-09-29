const crypto = require('crypto');
const { q } = require('./db');

function hashSecret(value) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(value, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function verifySecret(value, stored) {
  const [salt, hash] = String(stored).split(':');
  if (!salt || !hash) return false;
  const actual = crypto.scryptSync(value, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(actual,'hex'), Buffer.from(hash,'hex'));
}
function randomCode() { return String(Math.floor(100000 + Math.random()*900000)); }
function randomToken() { return crypto.randomBytes(32).toString('hex'); }
function setSession(res, session) {
  const payload = Buffer.from(JSON.stringify(session)).toString('base64url');
  const sig = crypto.createHmac('sha256', process.env.SESSION_SECRET).update(payload).digest('base64url');
  res.cookie('session', `${payload}.${sig}`, {httpOnly:true, sameSite:'lax', secure:process.env.NODE_ENV==='production', maxAge:1000*60*60*12});
}
function readSession(req) {
  const raw = req.cookies?.session;
  if (!raw) return null;
  const [payload,sig] = raw.split('.');
  if (!payload || !sig) return null;
  const expected = crypto.createHmac('sha256', process.env.SESSION_SECRET).update(payload).digest('base64url');
  try { if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null; } catch { return null; }
  try { const data=JSON.parse(Buffer.from(payload,'base64url').toString()); if(data.exp < Date.now()) return null; return data; } catch { return null; }
}
function clearSession(res){res.cookie('session','',{httpOnly:true,maxAge:0,sameSite:'lax',secure:process.env.NODE_ENV==='production'});}
async function requireAuth(req,res,next){
  const s=readSession(req); if(!s) return res.status(401).json({error:'غير مصرح'});
  if(s.role==='captain'){
    const r=await q('SELECT id,name,phone,status,wallet_name,wallet_number,bank_name,bank_account,accountant_whatsapp FROM captains WHERE id=$1',[s.id]);
    if(!r.rows[0] || r.rows[0].status!=='active') return res.status(401).json({error:'الحساب غير فعال'});
    req.user={role:'captain',...r.rows[0]};
  } else req.user=s;
  next();
}
function requireAdmin(req,res,next){ if(req.user?.role!=='admin') return res.status(403).json({error:'صلاحية الإدارة مطلوبة'}); next(); }
function requireCaptain(req,res,next){ if(req.user?.role!=='captain') return res.status(403).json({error:'صلاحية الكابتن مطلوبة'}); next(); }
module.exports={hashSecret,verifySecret,randomCode,setSession,readSession,clearSession,requireAuth,requireAdmin,requireCaptain};
