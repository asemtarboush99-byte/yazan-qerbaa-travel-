require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');
const { q, initDb, pool } = require('./db');
const { hashSecret, verifySecret, randomCode, setSession, readSession, clearSession, requireAuth, requireAdmin, requireCaptain } = require('./auth');

const app = express();
app.use(express.json({limit:'1mb'}));
app.use(cookieParser());
app.use(express.urlencoded({extended:true}));
app.use(express.static(path.join(__dirname,'..','public'), {maxAge:'1h'}));
app.disable('x-powered-by');

const num = v => Number(v || 0);
const money = v => Math.round(num(v)*1000)/1000;
const normalizePhone = p => String(p||'').replace(/[^0-9+]/g,'');

// توجيه الروابط تلقائياً
app.get('/admin.html', (req, res) => res.redirect('/admin/captains.html'));
app.get('/captain.html', (req, res) => res.redirect('/captain/dashboard.html'));

app.get('/api/me', requireAuth, (req,res)=>res.json({user:req.user}));

// --- المصادقة وتدفق الدخول والخروج ---
app.post('/api/auth/admin/login', (req,res)=>{
  if(String(req.body.password||'') !== String(process.env.ADMIN_PASSWORD||'')) return res.status(401).json({error:'كلمة السر غير صحيحة'});
  setSession(res,{role:'admin',exp:Date.now()+12*60*60*1000}); 
  res.json({ok:true,role:'admin'});
});

app.post('/api/auth/captain/login', async (req,res,next)=>{
  try{
    const phone=normalizePhone(req.body.phone); 
    const code=String(req.body.code||'');
    const r=await q('SELECT * FROM captains WHERE phone=$1 AND status<>\'deleted\'',[phone]);
    const c=r.rows[0]; 
    if(!c || !verifySecret(code,c.code_hash)) return res.status(401).json({error:'رقم الهاتف أو الكود غير صحيح'});
    if(c.status!=='active') return res.status(403).json({error:'الحساب موقوف مؤقتاً'});
    setSession(res,{role:'captain',id:c.id,exp:Date.now()+12*60*60*1000}); 
    res.json({ok:true,role:'captain'});
  }catch(e){next(e)}
});

app.post('/api/auth/logout',(req,res)=>{clearSession(res);res.json({ok:true})});

// --- لوحة الأدمن Dashboard ---
app.get('/api/admin/dashboard',requireAuth,requireAdmin,async(req,res,next)=>{
 try{
  const [c,o,l,p]=await Promise.all([
   q("SELECT COUNT(*)::int count, COUNT(*) FILTER(WHERE status='active')::int active FROM captains WHERE status<>'deleted'"),
   q("SELECT COUNT(*)::int count, COALESCE(SUM(value),0) value, COALESCE(SUM(commission),0) commission FROM orders WHERE created_at >= date_trunc('day',NOW())"),
   q("SELECT COALESCE(SUM(CASE WHEN type IN ('passenger_production','order_production','manual_credit') THEN amount ELSE 0 END),0) production, COALESCE(SUM(CASE WHEN type IN ('passenger_consumption','order_consumption','group_floor','commission','manual_debit') THEN amount ELSE 0 END),0) consumption FROM ledger_entries WHERE created_at >= date_trunc('day',NOW())"),
   q("SELECT COALESCE(SUM(amount),0) amount FROM payments WHERE status='paid' AND created_at >= date_trunc('day',NOW())")
  ]);
  res.json({captains:c.rows[0],orders:o.rows[0],ledger:l.rows[0],payments:p.rows[0]});
 }catch(e){next(e)}
});

// --- إدارة الكباتن ---
app.get('/api/admin/captains',requireAuth,requireAdmin,async(req,res,next)=>{try{
 const search=String(req.query.search||'').trim();
 const r=await q(`SELECT c.*, 
 COALESCE(SUM(CASE WHEN l.type IN ('passenger_production','order_production','manual_credit') THEN l.amount WHEN l.type IN ('passenger_consumption','order_consumption','group_floor','commission','manual_debit','payment') THEN -l.amount ELSE 0 END),0) balance,
 COALESCE(SUM(CASE WHEN l.type IN ('passenger_production','order_production','manual_credit') THEN l.amount ELSE 0 END),0) production,
 COALESCE(SUM(CASE WHEN l.type IN ('passenger_consumption','order_consumption','group_floor','commission','manual_debit') THEN l.amount ELSE 0 END),0) consumption
 FROM captains c LEFT JOIN ledger_entries l ON l.captain_id=c.id WHERE c.status<>'deleted' AND ($1='' OR c.name ILIKE '%'||$1||'%' OR c.phone ILIKE '%'||$1||'%') GROUP BY c.id ORDER BY c.created_at DESC`,[search]);
 res.json({captains:r.rows});
}catch(e){next(e)}});

app.post('/api/admin/captains',requireAuth,requireAdmin,async(req,res,next)=>{try{
 const rawName = req.body.name || req.body.captain_name || req.body.fullname || '';
 const rawPhone = req.body.phone || req.body.phone_number || '';
 const name = String(rawName).trim();
 const phone = normalizePhone(rawPhone);

 if(!name || !phone) return res.status(400).json({error:'الاسم ورقم الهاتف مطلوبان'});

 const code = randomCode(); 
 const r = await q('INSERT INTO captains(name,phone,code_hash) VALUES($1,$2,$3) RETURNING id,name,phone,status',[name,phone,hashSecret(code)]);
 res.status(201).json({captain:r.rows[0],code});
}catch(e){if(e.code==='23505') return res.status(409).json({error:'رقم الهاتف مستخدم مسبقاً'});next(e)}});

app.post('/api/admin/captains/:id/reset-code',requireAuth,requireAdmin,async(req,res,next)=>{try{
 const code = randomCode();
 const r = await q('UPDATE captains SET code_hash=$1, updated_at=NOW() WHERE id=$2 AND status<>\'deleted\' RETURNING id,name,phone',[hashSecret(code), req.params.id]);
 if(!r.rows[0]) return res.status(404).json({error:'الكابتن غير موجود'});
 res.json({ok:true, code, captain:r.rows[0]});
}catch(e){next(e)}});

app.get('/api/admin/captains/:id',requireAuth,requireAdmin,async(req,res,next)=>{try{
 const c=(await q('SELECT id,name,phone,status,wallet_name,wallet_number,bank_name,bank_account,accountant_whatsapp,created_at FROM captains WHERE id=$1',[req.params.id])).rows[0]; 
 if(!c)return res.status(404).json({error:'الكابتن غير موجود'});
 const [ledger,orders,payments]=await Promise.all([
  q('SELECT * FROM ledger_entries WHERE captain_id=$1 ORDER BY created_at DESC LIMIT 100',[c.id]),
  q('SELECT * FROM orders WHERE captain_id=$1 ORDER BY created_at DESC LIMIT 100',[c.id]),
  q('SELECT * FROM payments WHERE captain_id=$1 ORDER BY created_at DESC LIMIT 100',[c.id])
 ]); 
 res.json({captain:c,ledger:ledger.rows,orders:orders.rows,payments:payments.rows});
}catch(e){next(e)}});

app.patch('/api/admin/captains/:id/status',requireAuth,requireAdmin,async(req,res,next)=>{try{
 const status=['active','paused','deleted'].includes(req.body.status)?req.body.status:null;
 if(!status)return res.status(400).json({error:'حالة غير صحيحة'});
 await q('UPDATE captains SET status=$1,updated_at=NOW() WHERE id=$2',[status,req.params.id]);
 res.json({ok:true});
}catch(e){next(e)}});

app.put('/api/admin/captains/:id/payment-profile',requireAuth,requireAdmin,async(req,res,next)=>{try{
 await q('UPDATE captains SET wallet_name=$1,wallet_number=$2,bank_name=$3,bank_account=$4,accountant_whatsapp=$5,updated_at=NOW() WHERE id=$6',
 [String(req.body.wallet_name||''),String(req.body.wallet_number||''),String(req.body.bank_name||''),String(req.body.bank_account||''),String(req.body.accountant_whatsapp||''),req.params.id]);
 res.json({ok:true});
}catch(e){next(e)}});

// --- الإعدادات Settings ---
app.get('/api/admin/settings',requireAuth,requireAdmin,async(req,res,next)=>{try{
 const r=await q('SELECT key,value FROM settings ORDER BY key');
 res.json(Object.fromEntries(r.rows.map(x=>[x.key,Number(x.value)])));
}catch(e){next(e)}});

app.put('/api/admin/settings',requireAuth,requireAdmin,async(req,res,next)=>{try{
 const client=await pool.connect();
 try{
  await client.query('BEGIN');
  for(const key of ['passenger_production','passenger_consumption','order_production','order_consumption','group_floor']){
   if(req.body[key]!==undefined) await client.query('INSERT INTO settings(key,value) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_at=NOW()',[key,money(req.body[key])]);
  }
  await client.query('COMMIT');
 }catch(e){await client.query('ROLLBACK');throw e;}finally{client.release();}
 res.json({ok:true});
}catch(e){next(e)}});

// --- العمليات السريعة Batch Entries ---
app.post('/api/admin/entries/batch',requireAuth,requireAdmin,async(req,res,next)=>{
 const client=await pool.connect();
 try{
  const captainId=Number(req.body.captain_id); 
  const passengerProduction=Math.max(0,Number(req.body.passenger_production||0)); 
  const passengerConsumption=Math.max(0,Number(req.body.passenger_consumption||0)); 
  const orderProduction=Math.max(0,Number(req.body.order_production||0)); 
  const orderConsumption=Math.max(0,Number(req.body.order_consumption||0)); 
  const groupFloorCount=Math.max(0,Number(req.body.group_floor_count||0));
  
  if(!captainId)return res.status(400).json({error:'الكابتن مطلوب'});
  const s=(await client.query('SELECT key,value FROM settings')).rows.reduce((a,x)=>(a[x.key]=Number(x.value),a),{}); 
  await client.query('BEGIN');
  const items=[['passenger_production',passengerProduction*s.passenger_production,'إنتاج ركاب'],['passenger_consumption',passengerConsumption*s.passenger_consumption,'استهلاك ركاب'],['order_production',orderProduction*s.order_production,'إنتاج Orders'],['order_consumption',orderConsumption*s.order_consumption,'استهلاك Orders'],['group_floor',groupFloorCount*s.group_floor,'أرضية جروب']];
  for(const [type,amount,note] of items) if(amount>0) await client.query('INSERT INTO ledger_entries(captain_id,type,amount,note) VALUES($1,$2,$3,$4)',[captainId,type,amount,note]);
  await client.query('COMMIT');
  res.json({ok:true,items:items.map(x=>({type:x[0],amount:x[1]}))});
 }catch(e){await client.query('ROLLBACK').catch(()=>{});next(e)}finally{client.release()}
});

// --- التسويات Adjustments ---
app.post('/api/admin/adjustments',requireAuth,requireAdmin,async(req,res,next)=>{try{
 const captainId=Number(req.body.captain_id), type=req.body.type, amount=money(req.body.amount), note=String(req.body.note||'');
 if(!captainId||!['manual_credit','manual_debit'].includes(type)||amount<=0)return res.status(400).json({error:'بيانات التعديل غير صحيحة'});
 await q('INSERT INTO ledger_entries(captain_id,type,amount,note) VALUES($1,$2,$3,$4)',[captainId,type,amount,note]);
 res.json({ok:true});
}catch(e){next(e)}});

// --- الطلبات Orders ---
app.post('/api/admin/orders',requireAuth,requireAdmin,async(req,res,next)=>{const client=await pool.connect();try{
 const captainId=Number(req.body.captain_id), value=money(req.body.value), commission=money(req.body.commission), productionProfit=money(req.body.production_profit), consumption=money(req.body.consumption), customer=String(req.body.customer_name||''), note=String(req.body.note||'');
 if(!captainId)return res.status(400).json({error:'اختر الكابتن'});
 const orderNo='ORD-'+Date.now(); 
 await client.query('BEGIN');
 const o=(await client.query('INSERT INTO orders(captain_id,customer_name,order_number,value,commission,production_profit,consumption,note) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *',[captainId,customer,orderNo,value,commission,productionProfit,consumption,note])).rows[0];
 if(productionProfit>0)await client.query('INSERT INTO ledger_entries(captain_id,type,amount,reference_type,reference_id,note) VALUES($1,\'order_production\',$2,\'order\',$3,$4)',[captainId,productionProfit,o.id,'ربح أوردر']);
 if(consumption>0)await client.query('INSERT INTO ledger_entries(captain_id,type,amount,reference_type,reference_id,note) VALUES($1,\'order_consumption\',$2,\'order\',$3,$4)',[captainId,consumption,o.id,'استهلاك أوردر']);
 if(commission>0)await client.query('INSERT INTO ledger_entries(captain_id,type,amount,reference_type,reference_id,note) VALUES($1,\'commission\',$2,\'order\',$3,$4)',[captainId,commission,o.id,'عمولة أوردر']);
 await client.query('COMMIT');
 res.status(201).json({order:o});
}catch(e){await client.query('ROLLBACK').catch(()=>{});next(e)}finally{client.release()}});

// --- الدفعات Payments ---
app.post('/api/admin/payments',requireAuth,requireAdmin,async(req,res,next)=>{const client=await pool.connect();try{
 const captainId=Number(req.body.captain_id), amount=money(req.body.amount), method=String(req.body.method||'cash'), note=String(req.body.note||''); 
 if(!captainId||amount<=0)return res.status(400).json({error:'المبلغ غير صحيح'});
 await client.query('BEGIN');
 const p=(await client.query('INSERT INTO payments(captain_id,amount,method,status,note,paid_at) VALUES($1,$2,$3,\'paid\',$4,NOW()) RETURNING *',[captainId,amount,method,note])).rows[0];
 await client.query('INSERT INTO ledger_entries(captain_id,type,amount,reference_type,reference_id,note) VALUES($1,\'payment\',$2,\'payment\',$3,$4)',[captainId,amount,p.id,'دفعة']);
 await client.query('COMMIT');
 res.status(201).json({payment:p});
}catch(e){await client.query('ROLLBACK').catch(()=>{});next(e)}finally{client.release()}});

// --- التقارير Reports ---
app.get('/api/admin/reports',requireAuth,requireAdmin,async(req,res,next)=>{try{
 const from=req.query.from||new Date(Date.now()-30*864e5).toISOString().slice(0,10), to=req.query.to||new Date().toISOString().slice(0,10);
 const r=await q(`SELECT DATE(created_at) day,
 COALESCE(SUM(CASE WHEN type IN ('passenger_production','order_production','manual_credit') THEN amount ELSE 0 END),0) production,
 COALESCE(SUM(CASE WHEN type IN ('passenger_consumption','order_consumption','group_floor','commission','manual_debit') THEN amount ELSE 0 END),0) costs,
 COALESCE(SUM(CASE WHEN type='payment' THEN amount ELSE 0 END),0) payments
 FROM ledger_entries WHERE created_at >= $1::date AND created_at < ($2::date + INTERVAL '1 day') GROUP BY DATE(created_at) ORDER BY day DESC`,[from,to]);
 res.json({from,to,rows:r.rows});
}catch(e){next(e)}});

// --- واجهة الكابتن Captain Endpoints ---
app.get('/api/captain/dashboard',requireAuth,requireCaptain,async(req,res,next)=>{try{
 const id=req.user.id; 
 const [sum,orders,ledger]=await Promise.all([
  q(`SELECT COALESCE(SUM(CASE WHEN type IN ('passenger_production','order_production','manual_credit') THEN amount ELSE 0 END),0) production, COALESCE(SUM(CASE WHEN type IN ('passenger_consumption','order_consumption','group_floor','commission','manual_debit') THEN amount ELSE 0 END),0) costs, COALESCE(SUM(CASE WHEN type='payment' THEN amount ELSE 0 END),0) payments FROM ledger_entries WHERE captain_id=$1`,[id]),
  q('SELECT * FROM orders WHERE captain_id=$1 ORDER BY created_at DESC LIMIT 30',[id]),
  q('SELECT * FROM ledger_entries WHERE captain_id=$1 ORDER BY created_at DESC LIMIT 50',[id])
 ]); 
 const s=sum.rows[0];
 res.json({captain:req.user,summary:s,net:money(Number(s.production)-Number(s.costs)-Number(s.payments)),orders:orders.rows,ledger:ledger.rows});
}catch(e){next(e)}});

app.get('/api/captain/profile',requireAuth,requireCaptain,(req,res)=>res.json({captain:req.user}));
app.post('/api/captain/payment-request',requireAuth,requireCaptain,async(req,res,next)=>{try{
 const amount=money(req.body.amount);
 if(amount<=0)return res.status(400).json({error:'المبلغ غير صحيح'});
 const r=await q('INSERT INTO payments(captain_id,amount,method,status,note) VALUES($1,$2,$3,\'requested\',$4) RETURNING *',[req.user.id,amount,String(req.body.method||'whatsapp'),String(req.body.note||'طلب من الكابتن')]);
 res.status(201).json({payment:r.rows[0]});
}catch(e){next(e)}});

app.get('/health',async(req,res)=>{try{await q('SELECT 1');res.json({ok:true})}catch(e){res.status(503).json({ok:false})}});

app.get('/',(req,res)=>res.redirect('/login.html'));
app.use((req,res,next)=>{if(req.path.startsWith('/api/'))return res.status(404).json({error:'المسار غير موجود'});next()});
app.use((err,req,res,next)=>{console.error(err);res.status(500).json({error:'حدث خطأ في الخادم'});});

const port=Number(process.env.PORT||3000);
initDb().then(()=>app.listen(port,()=>console.log(`Aswad Al Tareeq running on ${port}`))).catch(e=>{console.error('DB init failed',e);process.exit(1)});
process.on('SIGTERM',async()=>{await pool.end();process.exit(0)});