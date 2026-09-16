const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '0.0.0.0';
const ROOT = __dirname;
const DATA_DIR = process.env.PAYTRACK_DATA_DIR || path.join(ROOT, 'data');
const DB = path.join(DATA_DIR, 'paytrack.json');
const PUBLIC = path.join(ROOT, 'public');
const SESSION_TTL_MS = 1000 * 60 * 60 * 8;
const SESSION_IDLE_MS = 1000 * 60 * 30;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const COOKIE_NAME = '__Host-paytrack_session';
const TRUSTED_ORIGIN = String(process.env.PAYTRACK_ORIGIN || '').replace(/\/$/, '');
const sessions = new Map();
const loginAttempts = new Map();
const requestBuckets = new Map();
fs.mkdirSync(DATA_DIR, { recursive: true });

function id(prefix='id'){ return prefix+'_'+crypto.randomBytes(8).toString('hex'); }
function freshDB(){
  return {schemaVersion:2,revision:0,updatedAt:null,owner:{username:'owner',displayName:'Amr & Mohamed Khaled'},accounts:[],companies:[],companyRequests:[],contactMessages:[],supportTickets:[],invoices:[],auditLog:[],tables:[],activeTableId:'',employees:[]};
}
function readDB(){ try{return JSON.parse(fs.readFileSync(DB,'utf8'));}catch{return freshDB();} }
function audit(db,auth,action,details=''){db.auditLog=Array.isArray(db.auditLog)?db.auditLog:[];db.auditLog.unshift({id:Date.now()+Math.random(),at:new Date().toISOString(),user:auth?.session?.username||'system',role:auth?.session?.role||'system',companyId:auth?.session?.companyId||null,action,details:String(details).slice(0,500)});db.auditLog=db.auditLog.slice(0,2000);}
function writeDB(db){
  const tmp=DB+'.tmp'; fs.writeFileSync(tmp,JSON.stringify(db,null,2),'utf8'); fs.renameSync(tmp,DB);
  try{const backupDir=path.join(DATA_DIR,'backups');fs.mkdirSync(backupDir,{recursive:true});const stamp=new Date().toISOString().replace(/[:.]/g,'-');fs.copyFileSync(DB,path.join(backupDir,'paytrack-'+stamp+'.json'));const files=fs.readdirSync(backupDir).filter(f=>f.endsWith('.json')).sort().reverse();files.slice(20).forEach(f=>{try{fs.unlinkSync(path.join(backupDir,f))}catch(_){}});}catch(_){ }
}
function json(res,code,obj,extra={}){const body=JSON.stringify(obj);res.writeHead(code,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',...securityHeaders(),...extra});res.end(body);}
function parseBody(req){return new Promise((resolve,reject)=>{let s='';req.on('data',c=>{s+=c;if(s.length>20*1024*1024)reject(new Error('Request too large.'));});req.on('end',()=>{try{resolve(s?JSON.parse(s):{})}catch(e){reject(new Error('Invalid JSON.'));}});req.on('error',reject);});}
function cleanUsername(v){return String(v||'').trim().toLowerCase();}
function publicUser(a){const co=a.companyId?getCompany(db,a.companyId):null;return {username:a.username,role:a.role,companyId:a.companyId||null,companyName:co?.name||a.companyName||null,createdAt:a.createdAt||null,canMigrate:a.role==='admin'&&co?.requestId==='legacy-migration'};}
function randomHex(bytes=32){return crypto.randomBytes(bytes).toString('hex');}
function hashPassword(password,salt=randomHex(16)){const iterations=600000;const hash=crypto.pbkdf2Sync(String(password),Buffer.from(salt,'hex'),iterations,32,'sha256').toString('hex');return `pbkdf2$${iterations}$${salt}$${hash}`;}
function verifyPassword(password,stored){try{const [scheme,it,salt,hash]=String(stored).split('$');if(scheme!=='pbkdf2')return false;const actual=crypto.pbkdf2Sync(String(password),Buffer.from(salt,'hex'),Number(it),32,'sha256').toString('hex');return crypto.timingSafeEqual(Buffer.from(actual,'hex'),Buffer.from(hash,'hex'));}catch{return false;}}
function validatePassword(p){return typeof p==='string'&&p.length>=15&&p.length<=200;}
function validateUsername(u){return typeof u==='string'&&/^[a-zA-Z0-9._-]{3,50}$/.test(u.trim());}
function findAccount(db,u){const n=cleanUsername(u);return (db.accounts||[]).find(a=>cleanUsername(a.username)===n);}
function getCompany(db,companyId){return (db.companies||[]).find(c=>c.id===companyId);}
function newCompany(name,requestId,plan='Standard'){return {id:id('co'),name:String(name||'Company').trim().slice(0,120)||'Company',status:'active',plan:String(plan||'Standard').slice(0,40),createdAt:Date.now(),requestId:requestId||null,tables:[],activeTableId:'',employees:[],settings:{currency:'$',taxRate:0.2,timezone:'Africa/Cairo',language:'en',brandColor:'#2563eb'},subscription:{status:'trial',plan:String(plan||'Standard'),employeeLimit:plan==='Enterprise'?1000:plan==='Professional'?250:50,trialEndsAt:Date.now()+14*86400000,renewalAt:null,paymentStatus:'unpaid'}};}
function ownerEnvAccounts(){
  // Non-secret Owner usernames/display names are fixed application configuration.
  // VibeNest only needs four secret environment variables: two passwords + two TOTP secrets.
  const owners=[
    {username:'amr',displayName:'Amr',password:process.env.PAYTRACK_OWNER_1_PASSWORD||''},
    {username:'mohamed.khaled',displayName:'Mohamed Khaled',password:process.env.PAYTRACK_OWNER_2_PASSWORD||''}
  ];
  owners.forEach((o,i)=>{
    if(!validateUsername(o.username)||!validatePassword(o.password))
      throw new Error(`Owner ${i+1} password is missing or invalid. Owner passwords must be at least 15 characters.`);
  });
  return owners;
}
function ensureOwnerAndMigrate(db){
  let changed=false;
  db.schemaVersion=4; db.companies=Array.isArray(db.companies)?db.companies:[]; db.companyRequests=Array.isArray(db.companyRequests)?db.companyRequests:[]; db.contactMessages=Array.isArray(db.contactMessages)?db.contactMessages:[]; db.supportTickets=Array.isArray(db.supportTickets)?db.supportTickets:[]; db.invoices=Array.isArray(db.invoices)?db.invoices:[]; db.auditLog=Array.isArray(db.auditLog)?db.auditLog:[]; db.accounts=Array.isArray(db.accounts)?db.accounts:[];
  const envOwners=ownerEnvAccounts();
  if(IS_PRODUCTION && envOwners.length!==2) throw new Error('Production requires exactly two Owner accounts.');
  if(IS_PRODUCTION && envOwners.some(o=>!ownerMfaSecret(o.username))) throw new Error('Production requires a TOTP MFA secret for each Owner account.');
  if(envOwners.length){
    const allowed=new Set(envOwners.map(o=>o.username));
    db.accounts.forEach(a=>{if(a.role==='owner'&&!allowed.has(cleanUsername(a.username))){a.role='disabled';a.disabledAt=Date.now();changed=true;}});
    envOwners.forEach(o=>{let a=findAccount(db,o.username);if(!a){a={username:o.username,passwordHash:hashPassword(o.password),role:'owner',companyId:null,displayName:o.displayName,createdAt:Date.now(),createdBy:'environment'};db.accounts.push(a);changed=true;}else{a.role='owner';a.companyId=null;a.displayName=o.displayName;if(!a.passwordHash||process.env.PAYTRACK_ROTATE_OWNER_PASSWORDS==='true'){a.passwordHash=hashPassword(o.password);delete a.password;changed=true;}}});
  } else if(IS_PRODUCTION) {
    throw new Error('Production startup requires both Owner passwords and both Owner TOTP secrets. No default Owner account is permitted in production.');
  } else {
    let owner=db.accounts.find(a=>a.role==='owner');
    if(!owner){owner={username:'owner',passwordHash:hashPassword('CHANGE-ME-BEFORE-DEPLOYMENT'),role:'owner',companyId:null,displayName:'Amr & Mohamed Khaled',createdAt:Date.now(),createdBy:'development-only'};db.accounts.push(owner);changed=true;}
    if(owner.password&&!owner.passwordHash){owner.passwordHash=hashPassword(owner.password);delete owner.password;changed=true;}
  }
  let bootstrapCompany=db.companies.find(c=>c.requestId==='legacy-migration');
  let bootstrapAdmin=db.accounts.find(a=>a.role==='admin');
  if(!bootstrapCompany && !bootstrapAdmin && db.companies.length===0){bootstrapCompany=newCompany('Main Company','legacy-migration','Standard');db.companies.push(bootstrapCompany);bootstrapAdmin={username:'admin',passwordHash:hashPassword('CHANGE-ME-BEFORE-DEPLOYMENT'),role:'admin',companyId:bootstrapCompany.id,companyName:bootstrapCompany.name,createdAt:Date.now(),createdBy:'system'};db.accounts.push(bootstrapAdmin);changed=true;}
  db.companies.forEach(c=>{c.settings={currency:'$',taxRate:0.2,timezone:'Africa/Cairo',language:'en',brandColor:'#2563eb',...(c.settings||{})};c.subscription={status:c.subscription?.status||'active',plan:c.subscription?.plan||c.plan||'Standard',employeeLimit:Number(c.subscription?.employeeLimit|| (c.plan==='Enterprise'?1000:c.plan==='Professional'?250:50)),trialEndsAt:c.subscription?.trialEndsAt||null,renewalAt:c.subscription?.renewalAt||null,paymentStatus:c.subscription?.paymentStatus||'unpaid',...(c.subscription||{})};});
  const legacyAccounts=db.accounts.filter(a=>a.role==='admin'||a.role==='user');
  if(db.tables?.length || db.employees?.length){let co=db.companies[0];if(!co){co=newCompany('Main Company','legacy-migration');db.companies.push(co);changed=true;}if(!co.tables?.length&&db.tables?.length){co.tables=db.tables;co.activeTableId=db.activeTableId||co.tables[0]?.id||'';changed=true;}if(!co.employees?.length&&db.employees?.length){co.employees=db.employees;changed=true;}legacyAccounts.forEach(a=>{if(!a.companyId){a.companyId=co.id;changed=true;}if(a.password&&!a.passwordHash){a.passwordHash=hashPassword(a.password);delete a.password;changed=true;}});db.tables=[];db.activeTableId='';db.employees=[];changed=true;}
  let admin=legacyAccounts.find(a=>a.role==='admin');if(admin&&!admin.companyId){const co=newCompany('Main Company','legacy-account');db.companies.push(co);admin.companyId=co.id;changed=true;}
  if(admin&&admin.password&&!admin.passwordHash){admin.passwordHash=hashPassword(admin.password);delete admin.password;changed=true;}
  return changed;
}
function newSession(account){const token=randomHex(32);const now=Date.now();sessions.set(token,{username:account.username,role:account.role,companyId:account.companyId||null,createdAt:now,lastSeenAt:now,expiresAt:now+SESSION_TTL_MS,lastReauthAt:now});return token;}
function parseCookie(req,name){const raw=String(req.headers.cookie||'');for(const part of raw.split(';')){const [k,...v]=part.trim().split('=');if(k===name)return decodeURIComponent(v.join('='));}return '';}
function getAuth(req){const token=parseCookie(req,COOKIE_NAME);const s=sessions.get(token);if(!s)return null;const now=Date.now();if(s.expiresAt<now||now-s.lastSeenAt>SESSION_IDLE_MS){sessions.delete(token);return null;}s.lastSeenAt=now;s.expiresAt=Math.min(s.createdAt+SESSION_TTL_MS,now+SESSION_TTL_MS);return {token,session:s};}
function sessionCookie(token,maxAge){const secure=IS_PRODUCTION?' Secure;':'';return `${COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Strict;${secure} Max-Age=${maxAge}`;}
function securityHeaders(){return {'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'strict-origin-when-cross-origin','Permissions-Policy':'camera=(),microphone=(),geolocation=()','Content-Security-Policy':"default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://unpkg.com; connect-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'", ...(IS_PRODUCTION?{'Strict-Transport-Security':'max-age=31536000; includeSubDomains; preload'}:{})};}
function base32Decode(input){const clean=String(input||'').toUpperCase().replace(/[^A-Z2-7]/g,'');let bits='',out=[];for(const ch of clean){const n='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(ch);if(n<0)continue;bits+=n.toString(2).padStart(5,'0');while(bits.length>=8){out.push(parseInt(bits.slice(0,8),2));bits=bits.slice(8);}}return Buffer.from(out);}
function totp(secret,when=Date.now()){const key=base32Decode(secret);const counter=Math.floor(when/1000/30);const msg=Buffer.alloc(8);msg.writeBigUInt64BE(BigInt(counter));const h=crypto.createHmac('sha1',key).update(msg).digest();const off=h[h.length-1]&15;const code=((h.readUInt32BE(off)&0x7fffffff)%1000000).toString().padStart(6,'0');return code;}
function verifyTotp(secret,code){if(!secret||!/^\d{6}$/.test(String(code||'')))return false;for(let i=-1;i<=1;i++){if(crypto.timingSafeEqual(Buffer.from(totp(secret,Date.now()+i*30000)),Buffer.from(String(code))))return true;}return false;}
function ownerMfaSecret(username){const u=cleanUsername(username);if(u==='amr')return process.env.PAYTRACK_OWNER_1_TOTP_SECRET||'';if(u==='mohamed.khaled')return process.env.PAYTRACK_OWNER_2_TOTP_SECRET||'';return '';}
function sameOrigin(req){if(!['POST','PUT','PATCH','DELETE'].includes(req.method))return true;const origin=String(req.headers.origin||'');if(!origin)return true;const expected=TRUSTED_ORIGIN||`${IS_PRODUCTION?'https':'http'}://${String(req.headers.host||'').replace(/\/$/,'')}`;return origin===expected;}
function requestAllowed(req,limit=120,windowMs=60000){const key=(req.socket.remoteAddress||'unknown')+'|'+Math.floor(Date.now()/windowMs);const count=(requestBuckets.get(key)||0)+1;requestBuckets.set(key,count);if(requestBuckets.size>5000){for(const k of requestBuckets.keys()){if(!k.endsWith(String(Math.floor(Date.now()/windowMs))))requestBuckets.delete(k);}}return count<=limit;}
function requireAuth(req,res,roleNeeded){const auth=getAuth(req);if(!auth){json(res,401,{error:'Please sign in again.'});return null;}if(roleNeeded&&(Array.isArray(roleNeeded)?!roleNeeded.includes(auth.session.role):auth.session.role!==roleNeeded)){json(res,403,{error:'You do not have permission for this action.'});return null;}return auth;}
function sanitizeEmployee(e){return {id:e.id,name:e.name,role:e.role,dailyLogs:e.dailyLogs||{}};}
function revision(){return Date.now();}
function publicFile(res,file){fs.readFile(file,(err,data)=>{if(err){res.writeHead(404,{'Content-Type':'text/plain'});return res.end('Not found');}const ext=path.extname(file).toLowerCase();const types={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.json':'application/json; charset=utf-8','.svg':'image/svg+xml'};res.writeHead(200,{'Content-Type':types[ext]||'application/octet-stream','Cache-Control':'no-store'});res.end(data);});}
function safeCompany(c){return {id:c.id,name:c.name,status:c.status,plan:c.plan||'Standard',createdAt:c.createdAt,employeeCount:Array.isArray(c.employees)?c.employees.length:0,tableCount:Array.isArray(c.tables)?c.tables.length:0,requestId:c.requestId||null,settings:c.settings||{},subscription:c.subscription||{status:'active',plan:c.plan||'Standard',employeeLimit:50,paymentStatus:'unpaid'}};}

const PAYTRACK_AI_API_URL = String(process.env.PAYTRACK_AI_API_URL || 'https://api.openai.com/v1/responses').trim();
const PAYTRACK_AI_MODEL = String(process.env.PAYTRACK_AI_MODEL || 'gpt-5.6-sol').trim();
const PAYTRACK_AI_API_KEY = String(process.env.PAYTRACK_AI_API_KEY || '').trim();
const PAYTRACK_AI_MAX_BODY = 2 * 1024 * 1024;
function extractAiText(data){
  if(typeof data?.output_text==='string') return data.output_text;
  const out=Array.isArray(data?.output)?data.output:[];
  const parts=[];
  for(const item of out){
    for(const c of (Array.isArray(item?.content)?item.content:[])){
      if(typeof c?.text==='string') parts.push(c.text);
    }
  }
  return parts.join('\n').trim();
}
function parseAiJson(text){
  const raw=String(text||'').trim();
  try{return JSON.parse(raw);}catch(_){
    const fenced=raw.match(/```(?:json)?\s*([\s\S]*?)\s*```/i);
    if(fenced) try{return JSON.parse(fenced[1]);}catch(_2){}
    const a=raw.indexOf('{'),b=raw.lastIndexOf('}');
    if(a>=0&&b>a) try{return JSON.parse(raw.slice(a,b+1));}catch(_3){}
  }
  return null;
}
function paytrackAiPrompt(mode,payload,role,language){
  const funcs=payload.functions||{};
  const state=payload.data||{};
  const allowed=role==='user'?['help','attendance','search','navigation','payroll']:Object.keys(funcs);
  return `You are PayTrack AI, the built-in operator for a payroll, attendance, HR and business-management SaaS.\n\n`+
    `The user may write in any natural language. Detect the user's language and answer in that language unless they explicitly request another language. Current UI language: ${language||'en'}.\n`+
    `User role: ${role}. Only use capabilities allowed for that role. Never bypass permissions.\n`+
    `Your job is to understand intent, reason over the supplied PayTrack state, and choose safe PayTrack actions. Do not invent data or claim an action succeeded unless it is represented in the response.\n`+
    `Available actions: ${JSON.stringify(funcs)}\n`+
    `Allowed action names for this role: ${JSON.stringify(allowed)}\n`+
    `Current PayTrack state: ${JSON.stringify(state)}\n\n`+
    (mode==='code_generation'||mode==='auto_code'
      ? `For code-generation mode, generate the smallest safe JavaScript patch that uses existing PayTrack functions/state when possible. Do not include secrets, credentials, destructive network calls, or code that attempts to escape the browser/server sandbox. Return JSON only with keys: reply, code.\nUser request: ${payload.message||''}`
      : `For command mode, return JSON only with keys: reply, actions. actions must be an array of {name,args}. Use as many actions as needed, but only from the allowed action names. For ordinary questions, actions may be empty. For changes, choose the smallest set of actions. Return the reply in the user's language.\nUser request: ${payload.message||''}`);
}
async function callPaytrackAI(mode,payload,role,language){
  if(!PAYTRACK_AI_API_KEY) return {configured:false,reply:'PayTrack AI is not connected yet. The owner must add PAYTRACK_AI_API_KEY in the server environment.'};
  const prompt=paytrackAiPrompt(mode,payload,role,language);
  const response=await fetch(PAYTRACK_AI_API_URL,{method:'POST',headers:{'Content-Type':'application/json','Authorization':`Bearer ${PAYTRACK_AI_API_KEY}`},body:JSON.stringify({model:PAYTRACK_AI_MODEL,input:prompt,store:false,max_output_tokens:6000})});
  if(!response.ok){const t=await response.text().catch(()=> '');throw new Error(`AI provider returned HTTP ${response.status}${t?': '+t.slice(0,300):''}`);}
  const data=await response.json();
  const text=extractAiText(data);
  const parsed=parseAiJson(text);
  if(!parsed) return {reply:text||'I could not interpret the model response safely.',actions:[]};
  return parsed;
}


let db=readDB();
if(ensureOwnerAndMigrate(db)){db.revision=revision();db.updatedAt=new Date().toISOString();writeDB(db);}

const server=http.createServer(async(req,res)=>{
  if(req.method==='OPTIONS'){res.writeHead(204,{...securityHeaders(),'Cache-Control':'no-store'});return res.end();}
  if(!sameOrigin(req))return json(res,403,{error:'Cross-origin request blocked.'});
  const requestLimit=(req.url||'').startsWith('/api/auth/')?30:120;
  if(!requestAllowed(req,requestLimit,60000))return json(res,429,{error:'Too many requests. Please try again shortly.'},{'Retry-After':'60'});
  const url=new URL(req.url,`http://${req.headers.host||'localhost'}`);
  if(req.method==='GET'&&(url.pathname==='/'||url.pathname==='/index.html'))return publicFile(res,path.join(PUBLIC,'index.html'));
  if(req.method==='GET'&&url.pathname==='/api/health')return json(res,200,{ok:true,app:'PayTrack',version:'4.3-ai-secure',revision:db.revision||0});

  if(req.method==='POST'&&url.pathname==='/api/paytrack-ai'){
    const auth=requireAuth(req,res,['owner','admin','user']); if(!auth)return;
    let p;try{p=await parseBody(req)}catch(e){return json(res,400,{error:e.message});}
    const raw=JSON.stringify(p);if(raw.length>PAYTRACK_AI_MAX_BODY)return json(res,413,{error:'AI request is too large.'});
    const mode=['command','code_generation','auto_code'].includes(String(p.mode))?String(p.mode):'command';
    if((mode==='code_generation'||mode==='auto_code')&&auth.session.role==='user')return json(res,403,{error:'Only company administrators can generate website code.'});
    try{
      const result=await callPaytrackAI(mode,p,auth.session.role,String(p.language||'en'));
      if(result.configured===false)return json(res,503,result);
      const allowed=auth.session.role==='user'?new Set(['help','attendance','search','navigation','payroll']):null;
      const actions=Array.isArray(result.actions)?result.actions.filter(a=>a&&typeof a.name==='string'&&(!allowed||allowed.has(a.name))).slice(0,12):[];
      audit(db,auth,'Used PayTrack AI',`${mode} • ${String(p.message||'').slice(0,180)}`);db.revision=revision();db.updatedAt=new Date().toISOString();writeDB(db);
      return json(res,200,{ok:true,reply:String(result.reply||''),actions,code:typeof result.code==='string'?result.code:'',model:PAYTRACK_AI_MODEL,language:String(p.language||'en')});
    }catch(e){return json(res,502,{error:'PayTrack AI could not complete the request.',details:IS_PRODUCTION?'':e.message});}
  }

  if(req.method==='POST'&&url.pathname==='/api/public/support'){let p;try{p=await parseBody(req)}catch(e){return json(res,400,{error:e.message});}const name=String(p.name||'').trim(),email=String(p.email||'').trim().toLowerCase(),subject=String(p.subject||'').trim(),message=String(p.message||'').trim();if(name.length<2||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||subject.length<2||message.length<2)return json(res,400,{error:'Please complete the support form.'});db.supportTickets.unshift({id:id('ticket'),name,email,subject,message,status:'open',priority:'normal',createdAt:new Date().toISOString(),updatedAt:new Date().toISOString()});audit(db,null,'New public support ticket',email);db.revision=revision();db.updatedAt=new Date().toISOString();writeDB(db);return json(res,200,{ok:true});}

  // Public access request: payment is deliberately manual until a payment provider is connected.
  if(req.method==='POST'&&url.pathname==='/api/public/company-request'){
    let p;try{p=await parseBody(req)}catch(e){return json(res,400,{error:e.message});}
    const companyName=String(p.companyName||'').trim(), contactName=String(p.contactName||'').trim(), email=String(p.email||'').trim().toLowerCase();
    if(companyName.length<2||contactName.length<2||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))return json(res,400,{error:'Please provide a company name, contact name, and valid email.'});
    const duplicate=(db.companyRequests||[]).find(r=>r.status==='pending'&&String(r.email||'').toLowerCase()===email&&Date.now()-Date.parse(r.createdAt||0)<86400000);
    if(duplicate)return json(res,409,{error:'A pending request already exists for this email address.'});
    const request={id:id('req'),companyName:companyName.slice(0,120),contactName:contactName.slice(0,120),email:email.slice(0,200),employeeCount:Math.max(0,Math.min(100000,Number(p.employeeCount)||0)),plan:['Standard','Professional','Enterprise'].includes(p.plan)?p.plan:'Standard',message:String(p.message||'').slice(0,1000),status:'pending',paymentStatus:'unpaid',createdAt:new Date().toISOString()};
    db.companyRequests.unshift(request);audit(db,{session:{username:'public',role:'public'}},'New company access request',companyName);db.revision=revision();db.updatedAt=new Date().toISOString();writeDB(db);return json(res,201,{ok:true,requestId:request.id,message:'Request submitted. The PayTrack owners can review it and contact you about payment and activation.'});
  }
  if(req.method==='POST'&&url.pathname==='/api/public/contact'){
    let p;try{p=await parseBody(req)}catch(e){return json(res,400,{error:e.message});}
    const name=String(p.name||'').trim(),email=String(p.email||'').trim().toLowerCase(),message=String(p.message||'').trim();
    if(name.length<2||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||message.length<2)return json(res,400,{error:'Please provide your name, email, and message.'});
    db.contactMessages.unshift({id:id('msg'),name:name.slice(0,120),email:email.slice(0,200),message:message.slice(0,2000),createdAt:new Date().toISOString(),status:'new'});db.contactMessages=db.contactMessages.slice(0,1000);audit(db,{session:{username:'public',role:'public'}},'New contact message',email);db.revision=revision();db.updatedAt=new Date().toISOString();writeDB(db);return json(res,201,{ok:true,message:'Your message was sent to the PayTrack owners.'});
  }

  if(req.method==='POST'&&url.pathname==='/api/auth/login'){
    let p;try{p=await parseBody(req)}catch(e){return json(res,400,{error:e.message});}
    const ip=req.socket.remoteAddress||'unknown',now=Date.now();const attempts=loginAttempts.get(ip)||{count:0,until:0};if(attempts.until>now&&attempts.count>=10)return json(res,429,{error:'Too many sign-in attempts. Please wait a few minutes.'});if(attempts.until<=now){attempts.count=0;attempts.until=now+5*60*1000;}
    const account=findAccount(db,p.username);if(!account||account.role==='disabled'||!verifyPassword(p.password,account.passwordHash)||(p.role&&account.role!==p.role)){attempts.count++;loginAttempts.set(ip,attempts);return json(res,401,{error:'Invalid username or password.'});}
    if(account.role==='owner'&&IS_PRODUCTION){const secret=ownerMfaSecret(account.username);if(!secret||!verifyTotp(secret,p.mfaCode)){attempts.count++;loginAttempts.set(ip,attempts);return json(res,401,{error:'Owner MFA verification failed.'});}}
    if(account.role!=='owner'){const co=getCompany(db,account.companyId);if(!co||co.status!=='active')return json(res,403,{error:'This company account is not currently active.'});const sub=co.subscription||{};if(sub.status==='expired'||(sub.status==='trial'&&sub.trialEndsAt&&Number(sub.trialEndsAt)<Date.now()))return json(res,403,{error:'This company subscription or trial has expired. Please contact PayTrack support.'});}
    loginAttempts.delete(ip);const token=newSession(account);audit(db,{session:{username:account.username,role:account.role,companyId:account.companyId}},'Signed in','');writeDB(db);return json(res,200,{ok:true,user:publicUser(account)},{'Set-Cookie':sessionCookie(token,Math.floor(SESSION_TTL_MS/1000))});
  }
  if(req.method==='GET'&&url.pathname==='/api/auth/me'){const auth=requireAuth(req,res);if(!auth)return;const a=findAccount(db,auth.session.username);if(!a)return json(res,401,{error:'Account no longer exists.'});return json(res,200,{user:publicUser(a)});}
  if(req.method==='POST'&&url.pathname==='/api/auth/logout'){const auth=getAuth(req);if(auth){audit(db,auth,'Signed out','');writeDB(db);sessions.delete(auth.token);}return json(res,200,{ok:true},{'Set-Cookie':sessionCookie('',0)});}

  if(req.method==='POST'&&url.pathname==='/api/auth/create-user'){
    const auth=requireAuth(req,res,'admin');if(!auth)return;let p;try{p=await parseBody(req)}catch(e){return json(res,400,{error:e.message});}
    const admin=findAccount(db,auth.session.username);if(!admin||!verifyPassword(p.adminPassword,admin.passwordHash))return json(res,403,{error:'Admin verification failed.'});if(!validateUsername(p.username))return json(res,400,{error:'Username must be 3–50 letters, numbers, dots, underscores, or hyphens.'});if(!validatePassword(p.password))return json(res,400,{error:'Password must be at least 15 characters.'});if(findAccount(db,p.username))return json(res,409,{error:'That username already exists.'});
    db.accounts.push({username:p.username.trim(),passwordHash:hashPassword(p.password),role:'user',companyId:auth.session.companyId,createdAt:Date.now(),createdBy:admin.username});audit(db,auth,'Created user',p.username.trim());db.revision=revision();db.updatedAt=new Date().toISOString();writeDB(db);return json(res,200,{ok:true,user:{username:p.username.trim(),role:'user',companyId:auth.session.companyId}});
  }
  if(req.method==='POST'&&url.pathname==='/api/auth/change-account'){
    const auth=requireAuth(req,res);if(!auth)return;let p;try{p=await parseBody(req)}catch(e){return json(res,400,{error:e.message});}const a=findAccount(db,auth.session.username);if(!a||!verifyPassword(p.currentPassword,a.passwordHash))return json(res,403,{error:'Current password is incorrect.'});const nextName=String(p.newUsername||a.username).trim();if(!validateUsername(nextName))return json(res,400,{error:'Username must be 3–50 letters, numbers, dots, underscores, or hyphens.'});if(p.newPassword&&!validatePassword(p.newPassword))return json(res,400,{error:'New password must be at least 15 characters.'});const other=db.accounts.find(x=>cleanUsername(x.username)===cleanUsername(nextName)&&x!==a);if(other)return json(res,409,{error:'That username is already in use.'});const old=a.username;a.username=nextName;if(p.newPassword)a.passwordHash=hashPassword(p.newPassword);a.updatedAt=Date.now();audit(db,auth,'Changed account',old+' → '+nextName);db.revision=revision();db.updatedAt=new Date().toISOString();writeDB(db);sessions.delete(auth.token);const token=newSession(a);return json(res,200,{ok:true,user:publicUser(a)},{'Set-Cookie':sessionCookie(token,Math.floor(SESSION_TTL_MS/1000))});
  }

  if(req.method==='GET'&&url.pathname==='/api/admin/backup'){
    const auth=requireAuth(req,res,'admin');if(!auth)return;const co=getCompany(db,auth.session.companyId);if(!co)return json(res,404,{error:'Company not found.'});audit(db,auth,'Downloaded company backup',co.name);writeDB(db);return json(res,200,{ok:true,exportedAt:new Date().toISOString(),company:safeCompany(co),tables:co.tables||[],activeTableId:co.activeTableId||'',employees:co.employees||[],auditLog:(db.auditLog||[]).filter(x=>x.companyId===co.id||x.role==='owner'||x.role==='system')});
  }

  // Owner Control Center APIs
  if(url.pathname.startsWith('/api/owner/')){
    const auth=requireAuth(req,res,'owner');if(!auth)return;
    if(['POST','PUT','PATCH','DELETE'].includes(req.method) && Date.now()-auth.session.lastReauthAt>15*60*1000){return json(res,401,{error:'Owner re-authentication required before sensitive platform changes.'});}

    if(req.method==='POST'&&url.pathname==='/api/owner/reauth'){
      let p;try{p=await parseBody(req)}catch(e){return json(res,400,{error:e.message});}
      const a=findAccount(db,auth.session.username);if(!a||!verifyPassword(p.password,a.passwordHash))return json(res,401,{error:'Owner re-authentication failed.'});
      auth.session.lastReauthAt=Date.now();return json(res,200,{ok:true});
    }
    if(req.method==='GET'&&url.pathname==='/api/owner/overview'){const companies=(db.companies||[]).map(safeCompany);const active=companies.filter(c=>c.status==='active').length;const trial=companies.filter(c=>c.subscription?.status==='trial').length;const paid=companies.filter(c=>c.subscription?.paymentStatus==='paid').length;const employees=companies.reduce((n,c)=>n+c.employeeCount,0);return json(res,200,{ok:true,companies,requests:db.companyRequests||[],messages:db.contactMessages||[],tickets:db.supportTickets||[],invoices:db.invoices||[],auditLog:db.auditLog||[],stats:{active,trial,paid,employees,totalCompanies:companies.length,pending:(db.companyRequests||[]).filter(r=>r.status==='pending').length,unreadMessages:(db.contactMessages||[]).filter(m=>m.status==='new').length,openTickets:(db.supportTickets||[]).filter(t=>t.status!=='closed').length}});}
    if(req.method==='POST'&&url.pathname==='/api/owner/request-action'){
      let p;try{p=await parseBody(req)}catch(e){return json(res,400,{error:e.message});}const r=(db.companyRequests||[]).find(x=>x.id===p.requestId);if(!r)return json(res,404,{error:'Request not found.'});
      const action=String(p.action||'');
      if(action==='reject'){r.status='rejected';r.reviewedAt=new Date().toISOString();audit(db,auth,'Rejected company request',r.companyName);db.revision=revision();db.updatedAt=new Date().toISOString();writeDB(db);return json(res,200,{ok:true,status:r.status});}
      if(action==='markPaid'){r.paymentStatus='paid';r.reviewedAt=new Date().toISOString();audit(db,auth,'Marked request paid',r.companyName);db.revision=revision();db.updatedAt=new Date().toISOString();writeDB(db);return json(res,200,{ok:true,paymentStatus:r.paymentStatus});}
      if(action==='approve'||action==='approveComplimentary'){
        if(r.status!=='pending')return json(res,400,{error:'Only pending requests can be approved.'});
        if(action==='approve'&&r.paymentStatus!=='paid')return json(res,400,{error:'Payment is required before activation. Use Approve complimentary when you intentionally waive payment.'});
        if(r.status==='approved')return json(res,400,{error:'Request is already approved.'});
        const co=newCompany(r.companyName,r.id,r.plan);db.companies.push(co);
        let base=cleanUsername(r.companyName).replace(/[^a-z0-9]+/g,'.').replace(/^\.|\.$/g,'').slice(0,30)||'company';let username=base+'.admin',i=2;while(findAccount(db,username))username=base+'.admin'+i++;
        const tempPassword=randomHex(7);db.accounts.push({username,passwordHash:hashPassword(tempPassword),role:'admin',companyId:co.id,companyName:co.name,createdAt:Date.now(),createdBy:'owner'});
        r.status='approved';r.accessType=action==='approveComplimentary'?'complimentary':'paid';r.paymentStatus=action==='approveComplimentary'?'waived':'paid';r.approvedAt=new Date().toISOString();r.companyId=co.id;r.adminUsername=username;audit(db,auth,'Approved company',co.name);db.revision=revision();db.updatedAt=new Date().toISOString();writeDB(db);
        return json(res,200,{ok:true,company:safeCompany(co),credentials:{username,password:tempPassword},warning:'This temporary password is shown once. Share it securely and ask the company admin to change it immediately.'});
      }
      return json(res,400,{error:'Unknown request action.'});
    }
    if(req.method==='POST'&&url.pathname==='/api/owner/company-action'){
      let p;try{p=await parseBody(req)}catch(e){return json(res,400,{error:e.message});}const co=getCompany(db,p.companyId);if(!co)return json(res,404,{error:'Company not found.'});const action=String(p.action||'');if(!['activate','suspend'].includes(action))return json(res,400,{error:'Unknown company action.'});co.status=action==='activate'?'active':'suspended';audit(db,auth,action==='activate'?'Activated company':'Suspended company',co.name);db.revision=revision();db.updatedAt=new Date().toISOString();writeDB(db);return json(res,200,{ok:true,status:co.status});
    }
    if(req.method==='POST'&&url.pathname==='/api/owner/company-plan'){let p;try{p=await parseBody(req)}catch(e){return json(res,400,{error:e.message});}const co=getCompany(db,p.companyId);if(!co)return json(res,404,{error:'Company not found.'});const plan=String(p.plan||'Standard');const limits={Standard:50,Professional:250,Enterprise:1000};if(!limits[plan])return json(res,400,{error:'Invalid plan.'});co.plan=plan;co.subscription={...(co.subscription||{}),plan,employeeLimit:Math.max(Number(p.employeeLimit)||limits[plan],co.employees?.length||0)};audit(db,auth,'Changed company plan',co.name+' → '+plan);db.revision=revision();db.updatedAt=new Date().toISOString();writeDB(db);return json(res,200,{ok:true,company:safeCompany(co)});}
    if(req.method==='POST'&&url.pathname==='/api/owner/subscription-action'){let p;try{p=await parseBody(req)}catch(e){return json(res,400,{error:e.message});}const co=getCompany(db,p.companyId);if(!co)return json(res,404,{error:'Company not found.'});const a=co.subscription=co.subscription||{};const action=String(p.action||'');if(action==='markPaid'){a.paymentStatus='paid';a.status='active';a.renewalAt=Date.now()+30*86400000;}else if(action==='startTrial'){a.status='trial';a.trialEndsAt=Date.now()+14*86400000;a.paymentStatus='unpaid';}else if(action==='extendTrial'){a.status='trial';a.trialEndsAt=Math.max(Date.now(),Number(a.trialEndsAt)||0)+(Number(p.days)||14)*86400000;}else if(action==='expire'){a.status='expired';}else{return json(res,400,{error:'Unknown subscription action.'});}audit(db,auth,'Updated subscription',co.name+' • '+action);db.revision=revision();db.updatedAt=new Date().toISOString();writeDB(db);return json(res,200,{ok:true,company:safeCompany(co)});}
    if(req.method==='POST'&&url.pathname==='/api/owner/ticket-action'){let p;try{p=await parseBody(req)}catch(e){return json(res,400,{error:e.message});}const t=(db.supportTickets||[]).find(x=>x.id===p.ticketId);if(!t)return json(res,404,{error:'Ticket not found.'});t.status=['open','pending','closed'].includes(p.status)?p.status:t.status;t.ownerNote=String(p.ownerNote||t.ownerNote||'').slice(0,2000);t.updatedAt=new Date().toISOString();audit(db,auth,'Updated support ticket',t.id);db.revision=revision();db.updatedAt=new Date().toISOString();writeDB(db);return json(res,200,{ok:true});}
    if(req.method==='POST'&&url.pathname==='/api/owner/message-action'){
      let p;try{p=await parseBody(req)}catch(e){return json(res,400,{error:e.message});}const m=(db.contactMessages||[]).find(x=>x.id===p.messageId);if(!m)return json(res,404,{error:'Message not found.'});m.status=String(p.status||'read')==='new'?'new':'read';audit(db,auth,'Updated contact message',m.email);db.revision=revision();db.updatedAt=new Date().toISOString();writeDB(db);return json(res,200,{ok:true,status:m.status});
    }
  }

  if(req.method==='POST'&&url.pathname==='/api/company/settings'){const auth=requireAuth(req,res,'admin');if(!auth)return;const co=getCompany(db,auth.session.companyId);if(!co)return json(res,404,{error:'Company not found.'});let p;try{p=await parseBody(req)}catch(e){return json(res,400,{error:e.message});}co.settings={...(co.settings||{}),currency:String(p.currency||co.settings.currency||'$').slice(0,8),taxRate:Math.max(0,Math.min(1,Number(p.taxRate ?? co.settings.taxRate ?? .2))),timezone:String(p.timezone||co.settings.timezone||'Africa/Cairo').slice(0,80),language:String(p.language||co.settings.language||'en').slice(0,12),brandColor:/^#[0-9a-f]{6}$/i.test(String(p.brandColor||''))?p.brandColor:co.settings.brandColor};audit(db,auth,'Updated company settings',co.name);db.revision=revision();db.updatedAt=new Date().toISOString();writeDB(db);return json(res,200,{ok:true,settings:co.settings});}
  if(req.method==='POST'&&url.pathname==='/api/company/ticket'){const auth=requireAuth(req,res,['admin','user']);if(!auth)return;const co=getCompany(db,auth.session.companyId);if(!co)return json(res,404,{error:'Company not found.'});let p;try{p=await parseBody(req)}catch(e){return json(res,400,{error:e.message});}const t={id:id('ticket'),companyId:co.id,name:auth.session.username,email:String(p.email||'').trim(),subject:String(p.subject||'').trim(),message:String(p.message||'').trim(),status:'open',priority:'normal',createdAt:new Date().toISOString(),updatedAt:new Date().toISOString()};if(t.subject.length<2||t.message.length<2)return json(res,400,{error:'Please complete the ticket.'});db.supportTickets.unshift(t);audit(db,auth,'Created support ticket',t.subject);db.revision=revision();db.updatedAt=new Date().toISOString();writeDB(db);return json(res,200,{ok:true,ticket:t});}
  if(req.method==='GET'&&url.pathname==='/api/company/tickets'){const auth=requireAuth(req,res,['admin','user']);if(!auth)return;const list=(db.supportTickets||[]).filter(t=>!t.companyId||t.companyId===auth.session.companyId);return json(res,200,{ok:true,tickets:list});}

  if(url.pathname==='/api/sync'){
    const auth=requireAuth(req,res);if(!auth)return;
    if(auth.session.role==='owner')return json(res,403,{error:'Owner accounts use the Owner Control Center.'});
    const co=getCompany(db,auth.session.companyId);if(!co)return json(res,404,{error:'Company workspace not found.'});
    if(req.method==='GET'){
      if(auth.session.role==='user')return json(res,200,{exists:true,revision:db.revision,updatedAt:db.updatedAt,company:{id:co.id,name:co.name},employees:(co.employees||[]).map(sanitizeEmployee)});
      return json(res,200,{exists:!!(co.tables?.length||co.employees?.length),revision:db.revision,updatedAt:db.updatedAt,company:safeCompany(co),tables:co.tables||[],activeTableId:co.activeTableId||'',employees:co.employees||[],auditLog:(db.auditLog||[]).filter(x=>x.companyId===co.id||x.role==='owner'||x.role==='system')});
    }
    if(req.method==='POST'){
      let p;try{p=await parseBody(req)}catch(e){return json(res,400,{error:e.message});}
      if(p.action==='syncState'){
        if(auth.session.role!=='admin')return json(res,403,{error:'Only company administrators can save payroll state.'});const st=p.state||{};co.tables=Array.isArray(st.tables)?st.tables:[];const limit=Number(co.subscription?.employeeLimit||0);const incoming=Array.isArray(st.employees)?st.employees:(co.tables.find(t=>t.id===st.activeTableId)?.employees||[]);if(limit&&incoming.length>limit)return json(res,403,{error:`Employee limit reached for the ${co.plan||'Standard'} plan (${limit}). Upgrade the company plan to add more employees.`});co.activeTableId=st.activeTableId||co.tables[0]?.id||'';const active=co.tables.find(t=>t.id===co.activeTableId)||co.tables[0];co.employees=Array.isArray(st.employees)?st.employees:(active?.employees||[]);audit(db,auth,'Saved company payroll state',p.migrate?'Initial migration':'Sync update');db.revision=revision();db.updatedAt=new Date().toISOString();writeDB(db);return json(res,200,{ok:true,revision:db.revision,updatedAt:db.updatedAt,migrated:!!p.migrate});
      }
      if(p.action==='submitAttendance'){
        if(auth.session.role!=='user')return json(res,403,{error:'Attendance submission is for user accounts.'});const date=String(p.date||''),rows=Array.isArray(p.attendance)?p.attendance:[];if(!/^\d{4}-\d{2}-\d{2}$/.test(date))return json(res,400,{error:'Invalid attendance date.'});const byId=new Map((co.employees||[]).map(e=>[String(e.id),e]));rows.forEach(r=>{const e=byId.get(String(r.employeeId));if(!e)return;e.dailyLogs=e.dailyLogs||{};e.dailyLogs[date]={status:['Present','Vacation','Absent'].includes(r.status)?r.status:'Present',overtime:Math.max(0,Number(r.overtime)||0)};});co.employees=Array.from(byId.values());const active=co.tables.find(t=>t.id===co.activeTableId);if(active)active.employees=co.employees;audit(db,auth,'Submitted attendance',date);db.revision=revision();db.updatedAt=new Date().toISOString();writeDB(db);return json(res,200,{ok:true,revision:db.revision,updatedAt:db.updatedAt,employees:(co.employees||[]).map(sanitizeEmployee)});
      }
      return json(res,400,{error:'Unknown action.'});
    }
  }
  res.writeHead(404,{'Content-Type':'text/plain'});res.end('Not found');
});
server.listen(PORT,HOST,()=>{console.log(`PayTrack multi-company server running on port ${PORT}`);console.log(`Local: http://localhost:${PORT}`);console.log(`Data: ${DB}`);});
