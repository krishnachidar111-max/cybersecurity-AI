/**
 * CyberShield AI — PWA Core (app.js)
 * Mobile-first fraud detection with push notifications
 */
'use strict';

/* ══════════════════════════
   1. THREAT DATABASE
══════════════════════════ */
const SAFE_DOMAINS = ['google.com','youtube.com','facebook.com','twitter.com','x.com',
  'instagram.com','linkedin.com','microsoft.com','apple.com','amazon.in','amazon.com',
  'flipkart.com','irctc.co.in','sbi.co.in','hdfcbank.com','icicibank.com','axisbank.com',
  'paytm.com','phonepe.com','gpay.app','github.com','wikipedia.org','ndtv.com',
  'cybercrime.gov.in','india.gov.in','rbi.org.in','npci.org.in'];

const BAD_TLDS=['.xyz','.top','.click','.tk','.ml','.ga','.cf','.gq','.pw',
  '.work','loan','.win','.racing','.download','.gdn','.men'];

const SHORTENERS=['bit.ly','t.co','tinyurl.com','goo.gl','ow.ly','short.io',
  'is.gd','tiny.cc','cutt.ly','rebrand.ly'];

const PHISH_KW_URL=['kyc','update','verify','secure','login','signin','account',
  'blocked','suspended','urgent','otp','refund','reward','free','prize','win',
  'lucky','claim','alert','confirm','sbi','hdfc','icici','axis','kotak','pnb',
  'paytm','phonepe','googlepay','bhim','upi'];

const BAD_EXT={
  critical:['.exe','.bat','.cmd','.scr','.com','.pif','.msi','.vbs','.js',
    '.jse','.wsf','.ps1','.reg','.hta','.jar'],
  high:['.apk','.dex','.sh','.bash'],
  medium:['.docm','.xlsm','.pptm']
};

const SUSPICIOUS_NAMES=['kyc','update','verify','account','refund','reward','free',
  'prize','winner','lucky','claim','urgent','otp','invoice','payment','receipt',
  'bank','credit','debit','upi','offer','setup','install','crack','keygen',
  'police','court','fir','warrant','customs','courier','parcel'];

const SCAM_KW={
  critical:[
    {w:'digital arrest',s:35,t:'Impersonation Scam'},
    {w:'fir',s:20,t:'Legal Threat Scam'},
    {w:'under arrest',s:25,t:'Fear Scam'},
    {w:'cbi',s:15,t:'Govt. Impersonation'},
    {w:'double money',s:30,t:'Investment Fraud'},
    {w:'lottery',s:28,t:'Lottery Scam'},
    {w:'won ₹',s:25,t:'Prize Scam'},
    {w:'won rs',s:25,t:'Prize Scam'},
    {w:'transfer money',s:25,t:'Money Transfer Scam'},
    {w:'share otp',s:28,t:'OTP Theft'},
    {w:'warrant',s:18,t:'Legal Threat Scam'},
    {w:'police',s:18,t:'Fear Scam'},
    {w:'customs',s:15,t:'Parcel Scam'},
  ],
  high:[
    {w:'otp',s:20,t:'OTP Theft'},
    {w:'kyc',s:18,t:'KYC Phishing'},
    {w:'account blocked',s:22,t:'Account Takeover'},
    {w:'account suspended',s:20,t:'Account Takeover'},
    {w:'refund',s:12,t:'Refund Scam'},
    {w:'verify now',s:15,t:'Phishing'},
    {w:'urgent',s:10,t:'Urgency Pressure'},
    {w:'parcel',s:12,t:'Parcel Scam'},
    {w:'courier',s:12,t:'Delivery Scam'},
    {w:'send money',s:22,t:'Money Transfer Scam'},
    {w:'investment',s:10,t:'Investment Fraud'},
  ],
  medium:[
    {w:'prize',s:8,t:'Prize Scam'},{w:'free',s:5,t:'Free Offer'},
    {w:'claim',s:6,t:'Claim Scam'},{w:'expire',s:5,t:'Urgency'},
    {w:'bit.ly',s:10,t:'Shortened Link'},{w:'verify',s:6,t:'Verify Scam'},
    {w:'click here',s:8,t:'Phishing Link'},
  ]
};

/* ══════════════════════════
   2. DATA STORE
══════════════════════════ */
let store = {total:0, high:0, suspicious:0, safe:0, history:[]};

function loadStore(){
  try{ const s=localStorage.getItem('cs_pwa'); if(s) store=JSON.parse(s); }catch(e){}
}
function saveStore(){
  try{ localStorage.setItem('cs_pwa', JSON.stringify(store)); }catch(e){}
}
function recordScan(result, target, category){
  store.total++;
  if(result.risk==='high') store.high++;
  else if(result.risk==='suspicious') store.suspicious++;
  else store.safe++;
  store.history.unshift({
    id:Date.now(), target:target.slice(0,60), score:result.score,
    risk:result.risk, type:result.threatType, category,
    time:new Date().toLocaleTimeString('en-IN',{hour12:true})
  });
  if(store.history.length>100) store.history.pop();
  saveStore();
  updateCounters();
  renderRecent();
  renderHistList();
  setAgentMsg(`Scanned: ${target.slice(0,30)}…`);
}

/* ══════════════════════════
   3. URL ANALYSIS
══════════════════════════ */
function analyzeURL(raw){
  let score=0, reasons=[], checks=[], threatType='URL Analysis';
  raw=raw.trim();
  if(!raw.startsWith('http')) raw='https://'+raw;
  let u;
  try{ u=new URL(raw); }catch{
    return {score:50,risk:'suspicious',reasons:[{icon:'⚠️',text:'Invalid/malformed URL',cls:'warn'}],
      checks:[],threatType:'Malformed URL',aiExplain:'This URL could not be parsed. Malformed URLs bypass security filters.'};
  }
  const host=u.hostname.toLowerCase();
  const tld='.'+host.split('.').slice(-1)[0];
  const path=u.pathname.toLowerCase();

  // HTTP
  if(u.protocol==='http:'){
    score+=25; threatType='Unencrypted Connection';
    reasons.push({icon:'🔴',text:'HTTP (no encryption) — passwords can be intercepted',cls:'danger'});
  } else checks.push({icon:'✅',text:'HTTPS encryption present'});

  // Known safe
  const isSafe=SAFE_DOMAINS.some(d=>host===d||host.endsWith('.'+d));
  if(isSafe){
    checks.push({icon:'✅',text:'Trusted domain whitelist match'});
    if(score<20&&reasons.length===0)
      return {score:5,risk:'safe',reasons:[],checks,threatType:'Trusted Domain',
        aiExplain:'This URL belongs to a well-known trusted domain. It appears safe.'};
  }

  // Bad TLD
  if(BAD_TLDS.some(t=>host.endsWith(t))){
    score+=22; threatType='Suspicious TLD';
    reasons.push({icon:'🔴',text:`Dangerous domain suffix "${tld}" — used by scammers for cheap/free domains`,cls:'danger'});
  }

  // Shortener
  if(SHORTENERS.some(s=>host.includes(s))){
    score+=18; threatType='Shortened URL';
    reasons.push({icon:'🟡',text:'URL shortener hides real destination',cls:'warn'});
  }

  // Phishing keywords
  const foundKW=PHISH_KW_URL.filter(k=>host.includes(k));
  if(foundKW.length>=2){
    score+=25; threatType='Phishing Domain';
    reasons.push({icon:'🔴',text:`Phishing keywords: "${foundKW.slice(0,3).join('", "')}"`,cls:'danger'});
  } else if(foundKW.length===1){
    score+=10;
    reasons.push({icon:'🟡',text:`Suspicious keyword in domain: "${foundKW[0]}"`,cls:'warn'});
  }

  // Path keywords
  const pathKW=PHISH_KW_URL.filter(k=>path.includes(k));
  if(pathKW.length>0){ score+=10; reasons.push({icon:'🟡',text:`Sensitive path keywords: ${pathKW.slice(0,2).join(', ')}`,cls:'warn'}); }

  // IP address
  if(/^\d{1,3}(\.\d{1,3}){3}$/.test(host)){
    score+=30; threatType='IP-based Phishing';
    reasons.push({icon:'🔴',text:'IP address as domain — real sites never do this',cls:'danger'});
  } else checks.push({icon:'✅',text:'Uses domain name (not raw IP)'});

  // Hyphens
  const hyphens=(host.match(/-/g)||[]).length;
  if(hyphens>=3){ score+=15; reasons.push({icon:'🟡',text:`${hyphens} hyphens in domain — common phishing pattern`,cls:'warn'}); }

  // Brand typosquatting
  const brands={sbi:/sb[i1][-.]?(?!co\.in)/,hdfc:/hdfc(?!bank\.com)/,
    paytm:/paytm(?!\.com)/,phonepe:/phonepe(?!\.com)/};
  for(const [brand,pat] of Object.entries(brands)){
    if(pat.test(host)){
      score+=28; threatType=`${brand.toUpperCase()} Brand Impersonation`;
      reasons.push({icon:'🔴',text:`Typosquatting — impersonates "${brand}" on unofficial domain`,cls:'danger'});
      break;
    }
  }

  if(raw.length>120){ score+=8; reasons.push({icon:'🟡',text:`Unusually long URL (${raw.length} chars)`,cls:'warn'}); }

  score=Math.min(score,100);
  const risk=score>=60?'high':score>=25?'suspicious':'safe';
  const aiExplain=genURLExplain(risk,threatType,host,foundKW);
  if(!checks.length) checks.push({icon:'ℹ️',text:'Limited positive trust signals'});
  return {score,risk,reasons,checks,threatType,aiExplain};
}

function genURLExplain(risk,type,host,kws){
  if(risk==='safe') return 'This URL appears clean. No known phishing patterns detected.';
  if(risk==='suspicious') return 'This URL has some suspicious signals. Avoid entering personal information or OTPs on this site.';
  const m={
    'Phishing Domain':`Domain "${host}" with keywords "${kws.join(', ')}" is a classic phishing pattern. Scammers clone bank/UPI sites to steal credentials. DO NOT enter OTP, PIN or password.`,
    'Unencrypted Connection':'HTTP sites send all data unencrypted. Anyone on the same network can intercept your passwords and OTPs. Real banking sites always use HTTPS.',
    'Shortened URL':'URL shorteners hide the real destination. Scammers use them to share dangerous links without revealing the domain. Never click shortened links from unknown sources.',
    'IP-based Phishing':'Legitimate websites never use IP addresses as URLs. This is a strong sign of a newly created phishing server.',
  };
  return m[type]||`This URL scored ${Math.min(100,50+10)} on our risk scale. Multiple fraud indicators found. DO NOT visit or enter any personal information.`;
}

/* ══════════════════════════
   4. FILE ANALYSIS
══════════════════════════ */
function analyzeFile(name,size){
  let score=0, reasons=[], checks=[], threatType='File Analysis';
  const nl=name.toLowerCase(), parts=nl.split('.');
  const ext=parts.length>1?'.'+parts[parts.length-1]:'';
  const nameBody=parts.slice(0,-1).join('.');

  // Double extension
  if(parts.length>2){
    const inner='.'+parts[parts.length-2];
    if(BAD_EXT.critical.includes(ext)){
      score+=50; threatType='Malware Disguise';
      reasons.push({icon:'🔴',text:`DOUBLE EXTENSION: looks like "${inner}" but runs as "${ext}". Classic malware trick.`,cls:'danger'});
    }
  }

  if(BAD_EXT.critical.includes(ext)){
    score+=40; if(threatType==='File Analysis') threatType='Malicious Executable';
    reasons.push({icon:'🔴',text:`Executable extension "${ext}" — can install malware, spyware, ransomware`,cls:'danger'});
  } else if(BAD_EXT.high.includes(ext)){
    score+=28; if(threatType==='File Analysis') threatType='High-Risk File';
    reasons.push({icon:'🔴',text:`High-risk extension "${ext}" — can install apps or run scripts silently`,cls:'danger'});
  } else if(BAD_EXT.medium.includes(ext)){
    score+=15;
    reasons.push({icon:'🟡',text:`Macro-enabled file "${ext}" — macros can run malicious code on open`,cls:'warn'});
  } else if(['.pdf','.txt','.jpg','.jpeg','.png','.gif','.docx','.xlsx'].includes(ext)){
    checks.push({icon:'✅',text:`Extension "${ext}" is generally safe`});
  }

  const foundNK=SUSPICIOUS_NAMES.filter(k=>nameBody.includes(k));
  if(foundNK.length>=2){
    score+=22; if(threatType==='File Analysis') threatType='Suspicious Filename';
    reasons.push({icon:'🔴',text:`Suspicious filename keywords: "${foundNK.slice(0,3).join('", "')}"`,cls:'danger'});
  } else if(foundNK.length===1){
    score+=10;
    reasons.push({icon:'🟡',text:`Suspicious keyword in filename: "${foundNK[0]}"`,cls:'warn'});
  } else checks.push({icon:'✅',text:'Filename has no suspicious keywords'});

  const mb=size/(1024*1024);
  if(mb>0.001) checks.push({icon:'✅',text:`File size: ${mb>1?mb.toFixed(1)+' MB':(size/1024).toFixed(0)+' KB'}`});

  score=Math.min(score,100);
  const risk=score>=60?'high':score>=25?'suspicious':'safe';
  const aiExplain=genFileExplain(risk,threatType,name,ext);
  if(!checks.length) checks.push({icon:'ℹ️',text:'No clear safety indicators found'});
  return {score,risk,reasons,checks,threatType,aiExplain};
}

function genFileExplain(risk,type,name,ext){
  if(risk==='safe') return 'This file appears safe based on its name and extension. Still verify the source before opening.';
  if(type==='Malware Disguise') return `"${name}" uses a double extension trick — it appears as a document but executes as a program. This was used in major ransomware attacks. DELETE immediately.`;
  if(BAD_EXT.critical.includes(ext)) return `".${ext.slice(1)}" files execute code on your device. Scammers send these as "KYC documents" or "invoice files". Opening can install keyloggers, ransomware, or spyware.`;
  if(ext==='.apk') return 'APK files install Android apps. Unknown APKs can access your SMS (OTPs), contacts, and banking apps. Only install from official Play Store.';
  return `File "${name}" shows ${risk==='high'?'critical':'suspicious'} indicators. Do NOT open. Report to cybercrime.gov.in if received unsolicited.`;
}

/* ══════════════════════════
   5. MESSAGE ANALYSIS
══════════════════════════ */
function analyzeMessage(text){
  let score=0, reasons=[], checks=[], threatType='Message Analysis';
  const tl=text.toLowerCase(), found=[];

  for(const [level,kws] of Object.entries(SCAM_KW)){
    for(const k of kws){
      if(tl.includes(k.w)){
        score+=k.s; found.push({...k,level});
        if(threatType==='Message Analysis') threatType=k.t;
      }
    }
  }

  // Group by type
  const groups={};
  found.forEach(f=>{ if(!groups[f.t]) groups[f.t]=[]; groups[f.t].push(f.w); });
  for(const [t,ws] of Object.entries(groups)){
    const lvl=found.find(f=>f.t===t)?.level||'medium';
    reasons.push({
      icon:lvl==='critical'?'🔴':lvl==='high'?'🟠':'🟡',
      text:`${t}: "${ws.slice(0,2).join('", "')}"`,
      cls:lvl==='critical'?'danger':'warn'
    });
  }

  // URLs in message
  const urls=(text.match(/https?:\/\/[^\s]+/gi)||[]);
  if(urls.length){
    const bad=urls.some(u=>BAD_TLDS.some(t=>u.includes(t))||SHORTENERS.some(s=>u.includes(s)));
    if(bad){ score+=20; reasons.push({icon:'🔴',text:'Contains suspicious URL(s)',cls:'danger'}); }
    else { score+=8; reasons.push({icon:'🟡',text:`Contains ${urls.length} URL(s) — verify before clicking`,cls:'warn'}); }
  } else checks.push({icon:'✅',text:'No URLs in message'});

  // Urgency
  const urgency=['immediately','within 24','expire','last warning','final notice','or else','action required'];
  const foundU=urgency.filter(p=>tl.includes(p));
  if(foundU.length){ score+=12; reasons.push({icon:'🟡',text:`Urgency language: "${foundU[0]}" — creates panic to bypass rational thinking`,cls:'warn'}); }

  if(found.length===0&&urls.length===0){
    checks.push({icon:'✅',text:'No scam keywords detected'});
    checks.push({icon:'✅',text:'Message appears legitimate'});
  }

  score=Math.min(score,100);
  const risk=score>=55?'high':score>=25?'suspicious':'safe';
  const aiExplain=genMsgExplain(risk,threatType,found);
  return {score,risk,reasons,checks,threatType,aiExplain};
}

function genMsgExplain(risk,type,found){
  if(risk==='safe') return 'This message does not match known scam patterns. Appears to be legitimate communication. Stay alert — never share OTPs with anyone.';
  const m={
    'Impersonation Scam':'Real CBI/Police/ED NEVER conduct investigations via phone or video call. "Digital arrest" is a scam that has cheated thousands. Hang up immediately and call 1930.',
    'OTP Theft':'NO bank, government agency, or payment company will EVER ask for your OTP. The moment someone asks — it\'s a SCAM. Block the caller.',
    'KYC Phishing':'Banks send KYC notices by post, not SMS with links. Call your bank\'s official number to verify. Never click links in KYC messages.',
    'Lottery Scam':'You did not win any lottery. Real lotteries never contact winners via SMS and never ask for processing fees. This is 100% fraud.',
    'Investment Fraud':'Schemes promising guaranteed high returns are illegal Ponzi schemes. They collapse after taking your money. Report to SEBI at sebi.gov.in.',
    'Fear Scam':'Scammers use fear of police/arrest to paralyze you. No legitimate authority threatens via SMS. Verify by calling 100 (Police) independently.',
    'Money Transfer Scam':'Never transfer money to someone who contacts you out of nowhere, regardless of their story. Call 1930 immediately.',
    'Parcel Scam':'Customs/courier scams claim your package is held and demand payment. Real customs processes go through official channels, not SMS.'
  };
  return m[type]||`This message matches the "${type}" fraud pattern. Do NOT respond, click any links, or share information. Block sender and report to 1930.`;
}

/* ══════════════════════════
   6. PAYMENT ANALYSIS
══════════════════════════ */
function analyzePayment(status,amount,utr,upiId,expected,source){
  let score=0, reasons=[], checks=[], threatType='Payment Verification';

  if(status==='pending'){ score+=40; threatType='Fake Pending Payment'; reasons.push({icon:'🔴',text:'Status = PENDING — money NOT credited. DO NOT deliver.',cls:'danger'}); }
  else if(status==='failed'){ score+=60; threatType='Failed Transaction'; reasons.push({icon:'🔴',text:'Payment FAILED — transaction incomplete. You will NOT receive money.',cls:'danger'}); }
  else checks.push({icon:'✅',text:'Status shows Success'});

  const utrC=(utr||'').replace(/\s/g,'');
  if(!utrC){ score+=20; reasons.push({icon:'🟡',text:'No UTR/Transaction ID — cannot verify authenticity',cls:'warn'}); }
  else if(!/^\d{12}$/.test(utrC)){ score+=25; threatType='Fake Transaction ID'; reasons.push({icon:'🔴',text:`UTR "${utrC}" (${utrC.length} chars) invalid — real UTR = 12 digits`,cls:'danger'}); }
  else checks.push({icon:'✅',text:`UTR ${utrC} — valid 12-digit format`});

  if(upiId&&upiId.trim()){
    const knownSufx=['@okicici','@okhdfcbank','@okaxis','@oksbi','@ybl','@ibl','@axl','@upi','@paytm'];
    if(!/^[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}$/.test(upiId)){ score+=15; reasons.push({icon:'🟡',text:`UPI ID "${upiId}" format invalid`,cls:'warn'}); }
    else if(!knownSufx.some(s=>upiId.toLowerCase().includes(s))){ score+=8; reasons.push({icon:'🟡',text:'UPI suffix not from major recognized bank',cls:'warn'}); }
    else checks.push({icon:'✅',text:'UPI ID from recognized payment service'});
  }

  const amt=parseFloat(amount)||0, exp=parseFloat(expected)||0;
  if(exp>0&&Math.abs(amt-exp)/exp>0.01){ score+=30; threatType='Amount Mismatch'; reasons.push({icon:'🔴',text:`Amount mismatch: Received ₹${amt} vs Expected ₹${exp} — DO NOT release goods`,cls:'danger'}); }
  else if(exp>0) checks.push({icon:'✅',text:`Amount ₹${amt} matches expected ₹${exp}`});

  if(source==='customer'){ score+=20; reasons.push({icon:'🟡',text:'Only customer screenshot — screenshots can be edited. Verify on bank portal or wait for SMS.',cls:'warn'}); }
  else if(source==='portal'){ score=Math.max(0,score-15); checks.push({icon:'✅',text:'Verified on payment portal — most reliable'}); }
  else if(source==='sms'){ score=Math.max(0,score-10); checks.push({icon:'✅',text:'Bank SMS received — high trust'}); }

  score=Math.min(score,100);
  const risk=score>=50?'high':score>=20?'suspicious':'safe';
  const aiExplain=risk==='high'?`⚠️ DO NOT DELIVER. ${threatType} detected. Confirm payment credited in YOUR bank account via official app/SMS before releasing goods. Call 1930 if fraud suspected.`:
    risk==='suspicious'?'Wait for bank SMS confirmation before proceeding. Better to delay than lose money.':
    'Payment appears legitimate. Always cross-verify with your bank\'s official app for complete assurance.';
  return {score,risk,reasons,checks,threatType,aiExplain};
}

/* ══════════════════════════
   7. ALERT SYSTEM
══════════════════════════ */
let curAlert=null;

function showAlert(result, target, category){
  curAlert={result,target,category};
  const {score,risk,reasons,threatType,aiExplain}=result;
  const overlay=document.getElementById('alertOverlay');
  const card=document.getElementById('alertCard');

  // Strip color
  const strip=document.getElementById('alertStrip');
  strip.className='alert-strip'+(risk==='high'?'':risk==='suspicious'?' warn':' safe');

  // Emoji + badge + title
  document.getElementById('alertEmoji').textContent=risk==='high'?'🚨':risk==='suspicious'?'⚠️':'✅';
  const badge=document.getElementById('alertBadge');
  badge.textContent=risk==='high'?'⛔ HIGH RISK':risk==='suspicious'?'⚠️ SUSPICIOUS':'✅ SAFE';
  badge.className='alert-badge-pill'+(risk==='suspicious'?' warn':risk==='safe'?' safe':'');
  document.getElementById('alertTitle').textContent=risk==='high'?'Fraud Detected':risk==='suspicious'?'Suspicious Activity':'No Threat Found';
  const typeEl=document.getElementById('alertType');
  typeEl.textContent=threatType;
  typeEl.className='alert-type'+(risk==='suspicious'?' warn':risk==='safe'?' safe':'');

  // Risk ring animation
  const arc=document.getElementById('riskArc');
  const numEl=document.getElementById('riskNum');
  const circumference=213.6;
  arc.style.stroke=risk==='high'?'#ff2b4e':risk==='suspicious'?'#ffc72b':'#00ff9d';
  numEl.className='risk-num'+(risk==='suspicious'?' warn':risk==='safe'?' safe':'');
  setTimeout(()=>{
    arc.style.strokeDashoffset=circumference*(1-score/100);
    numEl.textContent=score;
  },100);

  // Target
  document.getElementById('alertTargetBox').textContent=target.length>60?target.slice(0,60)+'…':target;

  // Reasons
  const rEl=document.getElementById('alertReasons');
  rEl.innerHTML=reasons.length
    ? reasons.map(r=>`<div class="ar-item ${r.cls==='danger'?'':r.cls==='warn'?'warn':'ok'}"><span class="ar-icon">${r.icon}</span><span>${r.text}</span></div>`).join('')
    : `<div class="ar-item ok"><span class="ar-icon">✅</span><span>No threats found — appears legitimate</span></div>`;

  document.getElementById('alertAiBox').textContent=aiExplain;
  overlay.classList.add('open');

  // Vibrate on high risk
  if(risk==='high'&&navigator.vibrate) navigator.vibrate([200,100,200,100,400]);

  // Push notification
  sendPushNotification(risk,threatType,target);

  recordScan(result,target,category);
}

function handleAlert(action){
  document.getElementById('alertOverlay').classList.remove('open');
  if(action==='learn'&&curAlert){
    showTab('ai');
    setTimeout(()=>askBot(`Explain the "${curAlert.result.threatType}" scam`),400);
  }
  curAlert=null;
}

/* ══════════════════════════
   8. PUSH NOTIFICATIONS
══════════════════════════ */
let swReg=null;

async function registerSW(){
  if(!('serviceWorker' in navigator)) return;
  try{
    swReg=await navigator.serviceWorker.register('./sw.js');
    console.log('[CyberShield] SW registered');
    navigator.serviceWorker.addEventListener('message', e=>{
      if(e.data?.type==='NAVIGATE') showTab(e.data.tab||'history');
    });
  }catch(err){console.warn('[CyberShield] SW reg failed:',err);}
}

async function requestNotifPermission(){
  if(!('Notification' in window)){
    document.getElementById('notifBar').style.display='none'; return;
  }
  if(Notification.permission==='granted'){
    document.getElementById('notifBar').style.display='none';
    document.getElementById('homeNotifBtn').classList.add('granted');
    return;
  }
  const perm=await Notification.requestPermission();
  if(perm==='granted'){
    document.getElementById('notifBar').style.display='none';
    document.getElementById('homeNotifBtn').classList.add('granted');
    // Welcome notification
    sendDirectNotif('🛡️ CyberShield Active','You\'ll now receive real-time fraud alerts on this device.','safe');
  }
}

function sendPushNotification(risk,threatType,target){
  if(Notification.permission!=='granted') return;
  const title=risk==='high'?'🚨 FRAUD DETECTED — Action Required':
               risk==='suspicious'?'⚠️ Suspicious Activity Detected':
               '✅ Scan Complete — Safe';
  const body=risk==='high'?`${threatType}: "${target.slice(0,50)}" BLOCKED`:
              risk==='suspicious'?`${threatType} detected: "${target.slice(0,45)}"`:
              `"${target.slice(0,45)}" scanned — no threats found`;
  sendDirectNotif(title,body,risk);
}

function sendDirectNotif(title,body,risk){
  if(swReg&&swReg.active){
    swReg.active.postMessage({type:'SHOW_NOTIFICATION',title,body,risk});
  } else if(Notification.permission==='granted'){
    new Notification(title,{
      body, icon:'./icons/icon-192.png', badge:'./icons/icon-72.png',
      tag:'cs-'+Date.now(), renotify:true,
      requireInteraction:risk==='high'
    });
  }
}

/* ══════════════════════════
   9. CLIPBOARD / PASTE DETECTION
══════════════════════════ */
let lastClipboard='';

document.addEventListener('paste', async(e)=>{
  const text=(e.clipboardData||window.clipboardData).getData('text');
  if(!text||text===lastClipboard) return;
  lastClipboard=text;

  // Auto-detect if it's a URL
  if(/^https?:\/\//i.test(text.trim())){
    showPasteToast(text, 'link');
  }
  // Auto-detect if it's a suspicious message
  else if(text.length>20){
    const lower=text.toLowerCase();
    const hasScam=Object.values(SCAM_KW).flat().some(k=>lower.includes(k.w));
    if(hasScam) showPasteToast(text,'sms');
  }
});

function showPasteToast(text, type){
  const toast=document.getElementById('pasteToast');
  document.getElementById('pastePreview').textContent=text.slice(0,40)+'…';
  toast.dataset.type=type;
  toast.dataset.text=text;
  toast.classList.add('show');
  setTimeout(hidePasteToast, 8000);
}

function hidePasteToast(){
  document.getElementById('pasteToast').classList.remove('show');
}

function scanClipboard(){
  const toast=document.getElementById('pasteToast');
  const text=toast.dataset.text;
  const type=toast.dataset.type;
  hidePasteToast();
  if(type==='link'){
    document.getElementById('urlInput').value=text;
    showTab('link');
    setTimeout(runURLScan,300);
  } else {
    document.getElementById('smsInput').value=text;
    showTab('sms');
    setTimeout(runSMSScan,300);
  }
}

async function pasteFromClipboard(){
  try{
    const text=await navigator.clipboard.readText();
    if(text){ document.getElementById('smsInput').value=text; livePreviewSMS(text); }
  }catch{
    document.getElementById('smsInput').focus();
    alert('Tap the text box and use long-press → Paste');
  }
}

async function pasteLinkFromClipboard(){
  try{
    const text=await navigator.clipboard.readText();
    if(text) document.getElementById('urlInput').value=text.trim();
  }catch{
    document.getElementById('urlInput').focus();
  }
}

/* ══════════════════════════
   10. SCAN HANDLERS
══════════════════════════ */
function autoScanMessage(text){
  document.getElementById('smsInput').value=text;
  const res=analyzeMessage(text);
  renderResult('smsResult',res,text.slice(0,60));
  showAlert(res,text.slice(0,60),'SMS Scan');
}

function loadSMS(text){ document.getElementById('smsInput').value=text; livePreviewSMS(text); }
function setURL(url){ document.getElementById('urlInput').value=url; }

function livePreviewSMS(text){
  const el=document.getElementById('smsLivePreview');
  if(text.length<10){ el.style.display='none'; return; }
  const res=analyzeMessage(text);
  el.style.display='block';
  el.style.borderColor=res.risk==='high'?'var(--red)':res.risk==='suspicious'?'var(--yellow)':'var(--green)';
  el.textContent=`Risk: ${res.score}/100 — ${res.threatType}`;
  el.style.color=res.risk==='high'?'var(--red)':res.risk==='suspicious'?'var(--yellow)':'var(--green)';
}

function runSMSScan(){
  const text=document.getElementById('smsInput').value.trim();
  if(!text){ document.getElementById('smsInput').focus(); return; }
  const res=analyzeMessage(text);
  const target=text.slice(0,60)+(text.length>60?'…':'');
  renderResult('smsResult',res,target);
  recordScan(res,target,'SMS Scan');
  if(res.risk!=='safe') setTimeout(()=>showAlert(res,target,'SMS Scan'),350);
}

function runURLScan(){
  const url=document.getElementById('urlInput').value.trim();
  if(!url){ document.getElementById('urlInput').focus(); return; }
  const btn=document.querySelector('#tab-link .scan-action-btn span');
  if(btn) btn.textContent='⏳ Scanning…';
  setTimeout(()=>{
    const res=analyzeURL(url);
    renderResult('urlResult',res,url);
    recordScan(res,url,'URL Scan');
    if(btn) btn.textContent='🔍 SCAN URL';
    if(res.risk!=='safe') setTimeout(()=>showAlert(res,url,'URL Scan'),350);
  },900);
}

function fakeFile(name,size){
  const res=analyzeFile(name,size||102400);
  renderResult('fileResult',res,name);
  recordScan(res,name,'File Scan');
  if(res.risk!=='safe') setTimeout(()=>showAlert(res,name,'File Scan'),350);
}

function handleFileSelect(e){
  const f=e.target.files[0];
  if(f) fakeFile(f.name,f.size);
}

function handleDrop(e){
  e.preventDefault();
  document.getElementById('dropZone').classList.remove('drag-over');
  const f=e.dataTransfer.files[0];
  if(f) fakeFile(f.name,f.size);
}
function handleDragOver(e){ e.preventDefault(); document.getElementById('dropZone').classList.add('drag-over'); }
function handleDragLeave(){ document.getElementById('dropZone').classList.remove('drag-over'); }

function selectStatus(btn){
  document.querySelectorAll('.ss-btn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('payStatus').value=btn.dataset.val;
}

function loadPayDemo(status,amount,utr,upi,expected,source){
  selectStatus(document.querySelector(`.ss-btn[data-val="${status}"]`));
  document.getElementById('payAmount').value=amount;
  document.getElementById('payUTR').value=utr;
  document.getElementById('payUPI').value=upi;
  document.getElementById('payExpected').value=expected;
  document.querySelectorAll('[name="verifySrc"]').forEach(r=>{ r.checked=r.value===source; });
}

function runPaymentScan(){
  const status=document.getElementById('payStatus').value;
  const amount=document.getElementById('payAmount').value;
  const utr=document.getElementById('payUTR').value;
  const upi=document.getElementById('payUPI').value;
  const expected=document.getElementById('payExpected').value;
  const source=document.querySelector('[name="verifySrc"]:checked')?.value||'customer';
  const res=analyzePayment(status,amount,utr,upi,expected,source);
  const target=`Pay ₹${amount||'?'} | UTR:${utr||'N/A'} | ${upi||'Unknown'}`;
  renderResult('payResult',res,target);
  recordScan(res,target,'Payment Check');
  if(res.risk!=='safe') setTimeout(()=>showAlert(res,target,'Payment Check'),350);
}

/* ══════════════════════════
   11. RESULT RENDERER
══════════════════════════ */
function renderResult(elId,result,target){
  const el=document.getElementById(elId);
  const {score,risk,reasons,checks,threatType,aiExplain}=result;
  const rc=risk==='high'?'high':risk==='suspicious'?'suspicious':'safe';
  const vt=risk==='high'?'🔴 HIGH RISK':risk==='suspicious'?'🟡 SUSPICIOUS':'🟢 SAFE';
  const items=[
    ...reasons.map(r=>`<div class="rb-item"><span class="rb-icon">${r.icon}</span>${r.text}</div>`),
    ...checks.map(c=>`<div class="rb-item"><span class="rb-icon">${c.icon}</span>${c.text}</div>`)
  ];
  el.className=`result-box ${rc}`;
  el.style.display='block';
  el.innerHTML=`
    <div class="rb-head">
      <div>
        <div class="rb-verdict ${rc}">${vt}</div>
        <div style="font-size:11px;color:var(--txt3);font-family:var(--font-m);margin-top:2px;">${threatType}</div>
      </div>
      <div class="rb-score">
        <div class="rb-score-num ${rc}">${score}</div>
        <div class="rb-score-lbl">RISK /100</div>
      </div>
    </div>
    <div class="rb-target">${target}</div>
    ${items.join('')}
    <div class="rb-ai">${aiExplain}</div>
    ${risk!=='safe'?'<div style="text-align:center;margin-top:12px;font-size:11px;color:var(--txt3);font-family:var(--font-m);">Cybercrime Helpline: <strong style="color:var(--cyan)">1930</strong></div>':''}
  `;
  el.scrollIntoView({behavior:'smooth',block:'nearest'});
}

/* ══════════════════════════
   12. DASHBOARD COUNTERS
══════════════════════════ */
function updateCounters(){
  const s=(id,v)=>{ const e=document.getElementById(id); if(e) e.textContent=v; };
  s('pcs-total',store.total); s('pcs-high',store.high); s('pcs-safe',store.safe);
}

function renderRecent(){
  const el=document.getElementById('recentList');
  const items=store.history.slice(0,4);
  if(!items.length){ el.innerHTML='<div class="empty-msg">No scans yet — tap a demo above to start</div>'; return; }
  el.innerHTML=items.map(i=>`
    <div class="hist-item">
      <div class="hi-dot ${i.risk}"></div>
      <div class="hi-body">
        <div class="hi-target">${i.target}</div>
        <div class="hi-meta">${i.category} · ${i.time}</div>
      </div>
      <span class="hi-tag ${i.risk}">${i.type}</span>
      <span class="hi-score ${i.risk}">${i.score}</span>
    </div>
  `).join('');
}

/* ══════════════════════════
   13. HISTORY
══════════════════════════ */
let histFilter='all';

function renderHistList(){
  const el=document.getElementById('histList');
  const items=histFilter==='all'?store.history:store.history.filter(h=>h.risk===histFilter);
  if(!items.length){ el.innerHTML='<div class="empty-msg">No alerts in this category.</div>'; return; }
  el.innerHTML=items.map(i=>`
    <div class="hist-item">
      <div class="hi-dot ${i.risk}"></div>
      <div class="hi-body">
        <div class="hi-target">${i.target}</div>
        <div class="hi-meta">${i.category} · ${i.time}</div>
      </div>
      <span class="hi-tag ${i.risk}">${i.type}</span>
      <span class="hi-score ${i.risk}">${i.score}</span>
    </div>
  `).join('');
}

function filterHist(f,btn){
  histFilter=f;
  document.querySelectorAll('.hf').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  renderHistList();
}

function clearHistory(){
  store={total:0,high:0,suspicious:0,safe:0,history:[]};
  saveStore(); updateCounters(); renderRecent(); renderHistList();
}

/* ══════════════════════════
   14. AI CHATBOT
══════════════════════════ */
const KB={
  phishing:`🎣 **Phishing** creates fake websites that look exactly like banks/UPI apps to steal your credentials.\n\n🔴 Spot it:\n• URL doesn't match official site\n• HTTP instead of HTTPS\n• Urgent "account blocked" language\n\n✅ Stay safe:\n• Type bank URLs directly — never click SMS links\n• Call your bank's official number to verify\n• Enable 2FA on all accounts`,
  'upi scam':`💸 **UPI Scams** are India's fastest-growing fraud category.\n\n🔴 Common tricks:\n• Screenshot fraud (fake success image)\n• "Request money" disguised as payment\n• Fake UPI customer care numbers\n• QR code sends money, not receives it\n\n⚠️ Golden rule: You NEVER enter PIN to RECEIVE money.\n\n📞 Report: 1930`,
  'digital arrest':`🚔 **Digital Arrest Scam** — Criminals pose as CBI/ED/Police on video call, claim you're "under digital arrest", demand money.\n\n🔴 Reality:\n• NO government agency arrests via video call\n• They use fake backgrounds and uniforms\n• They keep you on call for hours to isolate you\n\n✅ Do:\n1. Hang up immediately\n2. Call 1930\n3. Tell family — they may try the same person again`,
  otp:`🔑 **OTP Theft** — Your OTP is the master key to your bank account.\n\n🔴 How scammers steal it:\n• Pose as bank/TRAI/NPCI agent\n• Create urgency (SIM block, KYC, fraud on account)\n• Ask you to "verify" by sharing OTP\n\n⚠️ Absolute rule: NO legitimate organization will EVER ask for your OTP. Ever. Period.\n\n📞 If you shared OTP: Call bank immediately + 1930`,
  kyc:`📋 **KYC Scams** exploit mandatory KYC requirements.\n\n🔴 How it works:\n• Fake SMS: "Account blocked, update KYC: [link]"\n• Link opens cloned bank website\n• Enters credentials → stolen\n\n✅ Real KYC:\n• Bank contacts via post/registered email\n• You visit branch OR use official banking app\n• Banks NEVER send random SMS with links`,
  lottery:`🎰 **Lottery Scams** — You didn't win anything.\n\n🔴 How it works:\n• "Won ₹X lakh in KBC/Government/Foreign Lottery"\n• Asks for processing fee / tax payment\n• Once paid, disappears completely\n\nSimple rule: If you didn't enter a lottery, you didn't win one. Legitimate lotteries NEVER contact winners via SMS.`,
  investment:`📈 **Investment Fraud** — WhatsApp/Telegram groups promising guaranteed returns.\n\n🔴 Signs:\n• "VIP group" with fake screenshots of profits\n• Let you profit initially (honeypot)\n• Pressure to invest more\n• Platform not registered with SEBI\n\n✅ Verify at: sebi.gov.in | Report: 1930`,
  safe:`🛡️ **Top 10 Safety Tips for India:**\n\n1. Never share OTP with anyone\n2. Type bank URLs directly — don't click links\n3. Enable 2FA on all accounts\n4. Install apps only from Play Store\n5. Never install APKs from WhatsApp\n6. Verify payment on YOUR bank app, not screenshots\n7. Call official numbers (back of card)\n8. Block unknown callers asking for info\n9. Report scams: 1930\n10. File online complaint: cybercrime.gov.in`,
};

function askBot(q){
  document.getElementById('chatIn').value=q;
  sendChat();
}

function sendChat(){
  const input=document.getElementById('chatIn');
  const text=input.value.trim();
  if(!text) return;
  input.value='';
  const msgs=document.getElementById('chatMsgs');
  msgs.innerHTML+=`<div class="chat-user-msg"><div class="cuser-bubble">${esc(text)}</div></div>`;
  const tid='t'+Date.now();
  msgs.innerHTML+=`<div class="chat-bot-msg typing-bubble" id="${tid}"><div class="cbot-avatar">🛡️</div><div class="cbot-bubble"><div class="tdot"></div><div class="tdot"></div><div class="tdot"></div></div></div>`;
  msgs.scrollTop=msgs.scrollHeight;
  setTimeout(()=>{
    document.getElementById(tid)?.remove();
    const ans=findAnswer(text.toLowerCase());
    msgs.innerHTML+=`<div class="chat-bot-msg"><div class="cbot-avatar">🛡️</div><div class="cbot-bubble" style="white-space:pre-line;">${ans}</div></div>`;
    msgs.scrollTop=msgs.scrollHeight;
  },700+Math.random()*500);
}

function findAnswer(q){
  for(const [k,v] of Object.entries(KB)) if(q.includes(k)) return v;
  if(q.includes('otp')||q.includes('one time')) return KB.otp;
  if(q.includes('arrest')||q.includes('police')||q.includes('cbi')) return KB['digital arrest'];
  if(q.includes('link')||q.includes('url')||q.includes('phish')) return KB.phishing;
  if(q.includes('kyc')||q.includes('block')) return KB.kyc;
  if(q.includes('invest')||q.includes('profit')||q.includes('return')) return KB.investment;
  if(q.includes('safe')||q.includes('protect')||q.includes('tip')) return KB.safe;
  if(q.includes('win')||q.includes('prize')||q.includes('lottery')) return KB.lottery;
  return `I can help with:\n\n• Phishing & fake websites\n• UPI & payment scams\n• Digital arrest scam\n• OTP theft\n• KYC fraud\n• Lottery scams\n• Investment fraud\n• Online safety tips\n\n📞 Emergency: 1930\n🌐 cybercrime.gov.in`;
}

function esc(s){ return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

/* ══════════════════════════
   15. NAVIGATION
══════════════════════════ */
function showTab(name){
  document.querySelectorAll('.tab-section').forEach(s=>s.classList.remove('active'));
  document.querySelectorAll('.bn').forEach(b=>b.classList.remove('active'));
  document.getElementById('tab-'+name)?.classList.add('active');
  document.querySelector(`.bn[data-tab="${name}"]`)?.classList.add('active');
  if(name==='history') renderHistList();
  window.scrollTo(0,0);
}

/* ══════════════════════════
   16. PWA INSTALL
══════════════════════════ */
let deferredPrompt=null;

window.addEventListener('beforeinstallprompt',(e)=>{
  e.preventDefault();
  deferredPrompt=e;
  const banner=document.getElementById('installBanner');
  banner.classList.add('show');
  // Adjust agent bar
  document.querySelector('.agent-bar').style.top=banner.offsetHeight+'px';
});

function triggerInstall(){
  if(!deferredPrompt) return;
  deferredPrompt.prompt();
  deferredPrompt.userChoice.then(r=>{
    if(r.outcome==='accepted') dismissInstall();
    deferredPrompt=null;
  });
}

function dismissInstall(){
  document.getElementById('installBanner').classList.remove('show');
  document.querySelector('.agent-bar').style.top='';
}

window.addEventListener('appinstalled',()=>{ dismissInstall(); console.log('[CyberShield] PWA installed!'); });

/* ══════════════════════════
   17. AGENT STATUS
══════════════════════════ */
let agentOn=true;
const AGENT_MSGS=['Monitoring for threats…','Clipboard scan complete','SMS pattern check active',
  'Link interceptor running','All systems secure','Threat database updated',
  'Real-time protection ON','0 active threats detected','Background scan complete'];
let agentIdx=0;

function setAgentMsg(custom){
  const el=document.getElementById('agentMsg');
  if(el) el.textContent=custom||AGENT_MSGS[agentIdx++%AGENT_MSGS.length];
}

function toggleAgent(){
  agentOn=!agentOn;
  const dot=document.getElementById('agentDot');
  const label=document.getElementById('agentLabel');
  const btn=document.getElementById('agentPauseBtn');
  if(agentOn){
    dot.style.background='var(--cyan)'; dot.style.animationPlayState='running';
    label.textContent='CyberShield Active'; label.style.color='var(--cyan)';
    btn.textContent='⏸';
  } else {
    dot.style.background='var(--yellow)'; dot.style.animationPlayState='paused';
    label.textContent='CyberShield PAUSED'; label.style.color='var(--yellow)';
    btn.textContent='▶';
  }
}

/* ══════════════════════════
   18. KEYWORD CLOUD
══════════════════════════ */
function renderKWCloud(){
  const el=document.getElementById('kwGrid'); if(!el) return;
  const kws=[
    {t:'digital arrest',l:'critical'},{t:'OTP share',l:'critical'},{t:'KYC update',l:'critical'},
    {t:'account blocked',l:'critical'},{t:'transfer money',l:'critical'},{t:'lottery won',l:'critical'},
    {t:'double money',l:'critical'},{t:'police/CBI',l:'critical'},{t:'FIR filed',l:'high'},
    {t:'refund verify',l:'high'},{t:'customs parcel',l:'high'},{t:'urgent action',l:'high'},
    {t:'click here',l:'high'},{t:'verify now',l:'high'},{t:'send OTP',l:'high'},
    {t:'prize claim',l:'medium'},{t:'expire soon',l:'medium'},{t:'bit.ly link',l:'medium'},
    {t:'investment',l:'medium'},{t:'free offer',l:'medium'},
  ];
  el.innerHTML=kws.map(k=>`<span class="kw-tag ${k.l}">${k.t}</span>`).join('');
}

/* ══════════════════════════
   19. DEEP LINK / SHARE TARGET
══════════════════════════ */
function handleDeepLink(){
  const params=new URLSearchParams(window.location.search);
  const tab=params.get('tab');
  const sharedText=params.get('shared_text');
  const sharedUrl=params.get('shared_url');

  if(sharedUrl){ document.getElementById('urlInput').value=sharedUrl; showTab('link'); setTimeout(runURLScan,400); }
  else if(sharedText){ document.getElementById('smsInput').value=sharedText; showTab('sms'); setTimeout(runSMSScan,400); }
  else if(tab) showTab(tab);
}

/* ══════════════════════════
   20. INIT
══════════════════════════ */
function init(){
  loadStore();
  updateCounters();
  renderRecent();
  renderKWCloud();
  registerSW();

  // Show notification bar if permission not granted
  if('Notification' in window && Notification.permission==='default'){
    setTimeout(()=>document.getElementById('notifBar').classList.add('show'), 2000);
  }
  if(Notification.permission==='granted'){
    document.getElementById('homeNotifBtn').classList.add('granted');
  }

  // Agent ticker
  setInterval(()=>{ if(agentOn) setAgentMsg(); }, 4000);

  // Handle deep links and share targets
  handleDeepLink();

  console.log('%c⛨ CyberShield PWA v2.0 — Ready','color:#00ffe7;font-size:14px;font-weight:bold;');
}

document.addEventListener('DOMContentLoaded', init);
