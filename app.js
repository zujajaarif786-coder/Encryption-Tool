/* ============================================================
   FILE    : app.js
   PROJECT : CipherLab Pro — Information Security Project
   DESC    : Frontend JavaScript. Calls Python API when server
             is running, falls back to built-in JS ciphers.
   ============================================================ */

var M='xor',lastHex='',lastPlain='',kVis=false;
var fBytes=null,fName='',iBg='#0f1117',iFg='#e8d5a3',iAccent='#c9a84c',iTheme='dark';
var API_ONLINE=false;
var API_BASE='http://localhost:5000';

/* ── API status check ── */
function checkAPI(){
  fetch(API_BASE+'/api/status',{signal:AbortSignal.timeout(2000)})
    .then(function(r){return r.json();})
    .then(function(d){
      API_ONLINE=true;
      var el=document.getElementById('apiStatus');
      el.textContent='\u2022 Python API online ('+d.server+')';
      el.className='api-status online';
      toast('Python API connected.','info',2000);
    })
    .catch(function(){
      API_ONLINE=false;
      var el=document.getElementById('apiStatus');
      el.textContent='\u25CB Standalone mode (no server)';
      el.className='api-status';
    });
}

/* ── Toast ── */
function toast(msg,type,dur){
  type=type||'ok';dur=dur||2500;
  var w=document.getElementById('ta'),t=document.createElement('div');
  t.className='toast t'+type;t.textContent=msg;w.appendChild(t);
  setTimeout(function(){t.style.opacity='0';t.style.transform='translateY(8px)';t.style.transition='all .28s';setTimeout(function(){if(t.parentNode)t.parentNode.removeChild(t);},300);},dur);
}

/* ── Tab switching ── */
function go(t){
  M=t;
  ['xor','aes','caesar','file','compare','image'].forEach(function(id){
    document.getElementById('tab-'+id).classList.toggle('active',id===t);
  });
  var sk=(t==='xor'||t==='aes'||t==='caesar');
  show('keyCard',sk);show('textSec',sk);
  document.getElementById('caesarRow').style.display=t==='caesar'?'flex':'none';
  show('fileSec',t==='file');show('compareSec',t==='compare');show('imageSec',t==='image');
  if(t!=='xor')document.getElementById('traceBox').classList.remove('open');
  var lbl={xor:'XOR',aes:'AES-256',caesar:'CAESAR',file:'FILE XOR',compare:'COMPARE',image:'EXPORT'};
  document.getElementById('modePill').textContent='MODE \u00b7 '+(lbl[t]||t.toUpperCase());
  upd('sSt',lbl[t]||t.toUpperCase());upd('sSs','ready');
}
function show(id,v){document.getElementById(id).style.display=v?'block':'none';}
function upd(id,v){document.getElementById(id).textContent=v;}

/* ── Key strength ── */
function ks(k){
  if(!k||!k.length)return['None','kb0',0];
  if(k.length<4)return['Weak','kb1',15];
  if(k.length<8||!/[^a-zA-Z]/.test(k))return['Fair','kb2',50];
  if(k.length>=10&&/[A-Z]/.test(k)&&/[0-9!@#$%^&*]/.test(k))return['Strong','kb3',100];
  return['Good','kb2',72];
}

/* ── JS fallback ciphers (used when API offline) ── */
function jsXorEnc(text,key){
  var o=[];
  for(var i=0;i<text.length;i++)o.push((text.charCodeAt(i)^key.charCodeAt(i%key.length)).toString(16).padStart(2,'0').toUpperCase());
  return o.join(' ');
}
function jsXorDec(hex,key){
  var parts=hex.trim().split(/\s+/),o='';
  for(var i=0;i<parts.length;i++){var v=parseInt(parts[i],16);if(isNaN(v))return null;o+=String.fromCharCode(v^key.charCodeAt(i%key.length));}
  return o;
}
function jsCaesarEnc(text,sh){
  sh=((sh%26)+26)%26;
  return text.split('').map(function(c){
    if(c>='A'&&c<='Z')return String.fromCharCode(((c.charCodeAt(0)-65+sh)%26)+65);
    if(c>='a'&&c<='z')return String.fromCharCode(((c.charCodeAt(0)-97+sh)%26)+97);
    return c;
  }).join('');
}
function jsCaesarDec(text,sh){return jsCaesarEnc(text,26-sh);}

/* ── API call helper ── */
function apiPost(endpoint,body,onSuccess,onError){
  fetch(API_BASE+endpoint,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),signal:AbortSignal.timeout(5000)})
    .then(function(r){return r.json();})
    .then(function(d){if(d.status==='ok')onSuccess(d);else onError(d.message||'Server error.');})
    .catch(function(e){onError('API unreachable: '+e.message);});
}

/* ── Get shift ── */
function getShift(){return((parseInt(document.getElementById('shiftInput').value)||3)%26+26)%26||1;}

/* ── Encrypt ── */
function doEncrypt(){
  var text=document.getElementById('plainIn').value;
  var key=document.getElementById('keyInput').value;
  if(!text){toast('Please enter some text first.','err');return;}
  if((M==='xor'||M==='aes')&&!key){toast('Please enter a secret key.','err');return;}

  function applyResult(out){
    lastHex=out;lastPlain=text;
    document.getElementById('hexOut').value=out;
    document.getElementById('imgCipher').value=out;
    var sz=M==='xor'?out.split(' ').length:out.length;
    upd('hexPill',sz+(M==='xor'?' bytes':' chars'));upd('sO',sz);
    upd('sOs',M==='xor'?'hex bytes':'chars');
    upd('sSt','Encrypted');upd('sSs','success');
    document.getElementById('decWrap').style.display='none';
    if(M==='xor'){renderTrace(text,key);document.getElementById('traceBox').classList.add('open');}
    else document.getElementById('traceBox').classList.remove('open');
    toast('Encrypted successfully.','ok');
  }

  if(API_ONLINE){
    if(M==='xor'){
      apiPost('/api/xor/encrypt',{text:text,key:key},function(d){applyResult(d.encrypted);},function(e){toast('API error: '+e,'err');});
    } else if(M==='aes'){
      apiPost('/api/aes/encrypt',{text:text,key:key},function(d){applyResult(d.encrypted);},function(e){toast('API error: '+e,'err');});
    } else if(M==='caesar'){
      apiPost('/api/caesar/encrypt',{text:text,shift:getShift()},function(d){applyResult(d.encrypted);},function(e){toast('API error: '+e,'err');});
    }
  } else {
    var out='';
    if(M==='xor'){out=jsXorEnc(text,key);}
    else if(M==='aes'){out='[AES requires Python server — run: python api_server.py]';}
    else if(M==='caesar'){out=jsCaesarEnc(text,getShift());}
    applyResult(out);
  }
}

/* ── Decrypt ── */
function doDecrypt(){
  var cipher=document.getElementById('hexOut').value.trim();
  var key=document.getElementById('keyInput').value;
  if(!cipher){toast('No cipher text \u2014 encrypt first.','err');return;}
  if((M==='xor'||M==='aes')&&!key){toast('Please enter the secret key.','err');return;}

  function applyDecrypt(result){
    var orig=document.getElementById('plainIn').value,match=(result===orig);
    var box=document.getElementById('decOut');box.textContent=result;box.className='rbox has';
    var sp=document.createElement('span');sp.className='vbadge '+(match?'vok':'vfail');
    sp.textContent=match?'\u2713 Verification passed \u2014 original text recovered':'\u2715 Mismatch \u2014 wrong key or different text';
    var ve=document.getElementById('verEl');ve.innerHTML='';ve.appendChild(sp);
    document.getElementById('decWrap').style.display='block';
    upd('sSt','Decrypted');upd('sSs',match?'verified':'mismatch');
    toast(match?'Original text recovered.':'Decrypted \u2014 key mismatch.','ok');
  }

  if(API_ONLINE){
    if(M==='xor'){
      apiPost('/api/xor/decrypt',{cipher:cipher,key:key},function(d){applyDecrypt(d.decrypted);},function(e){toast('API error: '+e,'err');});
    } else if(M==='aes'){
      apiPost('/api/aes/decrypt',{cipher:cipher,key:key},function(d){applyDecrypt(d.decrypted);},function(e){toast('Decryption failed: '+e,'err');});
    } else if(M==='caesar'){
      apiPost('/api/caesar/decrypt',{cipher:cipher,shift:getShift()},function(d){applyDecrypt(d.decrypted);},function(e){toast('API error: '+e,'err');});
    }
  } else {
    var result='';
    if(M==='xor'){result=jsXorDec(cipher,key);if(result===null){toast('Invalid cipher text format.','err');return;}}
    else if(M==='aes'){toast('AES decrypt requires Python server \u2014 run: python api_server.py','err');return;}
    else if(M==='caesar'){result=jsCaesarDec(cipher,getShift());}
    applyDecrypt(result);
  }
}

/* ── Clear ── */
function clearAll(){
  document.getElementById('plainIn').value='';document.getElementById('hexOut').value='';
  document.getElementById('decWrap').style.display='none';document.getElementById('traceBox').classList.remove('open');
  lastHex='';lastPlain='';upd('sC','0');upd('sO','0');
  upd('plainPill','0 chars');upd('hexPill','0');upd('sSt','Idle');upd('sSs','cleared');
  toast('Cleared.','info');
}

/* ── Copy ── */
function copyHex(){
  if(!lastHex){toast('Nothing to copy yet.','err');return;}
  navigator.clipboard.writeText(lastHex).then(function(){
    var b=document.getElementById('copyBtn');b.textContent='Copied';
    setTimeout(function(){b.textContent='Copy';},2000);toast('Copied to clipboard.','info');
  }).catch(function(){toast('Copy failed.','err');});
}

/* ── XOR bit trace ── */
function toBin(n){return n.toString(2).padStart(8,'0');}
function renderBits(bin,c0,c1){
  return bin.split('').map(function(b){var d=document.createElement('div');d.className='bit '+(b==='1'?c1:c0);d.textContent=b;return d.outerHTML;}).join('');
}
function renderTrace(plain,key){
  var p=plain.charCodeAt(0),k=key.charCodeAt(0),r=p^k;
  var ph=r.toString(16).toUpperCase().padStart(2,'0');
  upd('traceBdg',"'"+plain[0]+"' \u2295 '"+key[0]+"'");
  var cards=document.getElementById('traceCards');cards.innerHTML='';
  [['Plain char',"'"+plain[0]+"' \u2192 "+p,''],
   ['Key char',"'"+key[0]+"' \u2192 "+k,''],
   ['XOR result',r+' \u2192 '+ph+'h',''],
   ['Verified',ph+"h \u2295 K = '"+plain[0]+"' \u2713",'var(--sage-d)']
  ].forEach(function(item){
    var tc=document.createElement('div');tc.className='tc';
    var lb=document.createElement('div');lb.className='tcl';lb.textContent=item[0];
    var vl=document.createElement('div');vl.className='tcv';vl.textContent=item[1];
    if(item[2])vl.style.color=item[2];
    tc.appendChild(lb);tc.appendChild(vl);cards.appendChild(tc);
  });
  var bw=document.getElementById('bitsWrap');bw.innerHTML='';
  var lbl=document.createElement('div');lbl.className='blbl';lbl.textContent='Binary XOR operation';bw.appendChild(lbl);
  function addRow(bin,c0,c1,ltext,lcol){
    var row=document.createElement('div');row.className='brow-b';row.innerHTML=renderBits(bin,c0,c1);
    if(ltext){var sp=document.createElement('span');sp.className='op';sp.style.cssText='margin-left:.35rem;font-size:.64rem;color:'+lcol;sp.textContent=ltext;row.appendChild(sp);}
    bw.appendChild(row);
  }
  addRow(toBin(p),'b0','b1',"'"+plain[0]+"' ("+p+')','var(--gold-d)');
  var or=document.createElement('div');or.className='brow-b';var os=document.createElement('span');os.className='op';os.textContent='\u2295';or.appendChild(os);bw.appendChild(or);
  addRow(toBin(k),'b0','b1',"'"+key[0]+"' ("+k+')','var(--mist)');
  var dl=document.createElement('div');dl.className='dln';bw.appendChild(dl);
  addRow(toBin(r),'br0','br1',ph+'h','var(--sage-d)');
}

/* ── File (client-side XOR, no server needed) ── */
function loadFile(e){
  var file=e.target.files[0];if(!file)return;
  if(file.size>5*1024*1024){toast('File too large \u2014 max 5 MB.','err');return;}
  fName=file.name;
  var nb=document.getElementById('fnBar');nb.textContent=file.name+' \u00b7 '+Math.round(file.size/1024)+' KB';nb.style.display='block';
  var r=new FileReader();
  r.onload=function(ev){
    fBytes=new Uint8Array(ev.target.result);
    document.getElementById('fEncBtn').disabled=false;document.getElementById('fDecBtn').disabled=false;
    upd('fStatus','Ready: '+fBytes.length+' bytes loaded.');toast('File loaded.','ok');
  };
  r.readAsArrayBuffer(file);
}
function xorBytes(bytes,key){var o=new Uint8Array(bytes.length);for(var i=0;i<bytes.length;i++)o[i]=bytes[i]^key.charCodeAt(i%key.length);return o;}
function dlBytes(bytes,name){
  var blob=new Blob([bytes],{type:'application/octet-stream'});
  var a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=name;
  document.body.appendChild(a);a.click();document.body.removeChild(a);
  setTimeout(function(){URL.revokeObjectURL(a.href);},1000);
}
function encFile(){
  if(!fBytes){toast('Load a file first.','err');return;}
  var key=document.getElementById('fileKey').value;if(!key){toast('Enter an encryption key.','err');return;}
  dlBytes(xorBytes(fBytes,key),'encrypted_'+fName);
  upd('fStatus','\u2713 Encrypted '+fBytes.length+' bytes \u2014 downloading.');toast('File encrypted and downloading.','ok');
}
function decFile(){
  if(!fBytes){toast('Load a file first.','err');return;}
  var key=document.getElementById('fileKey').value;if(!key){toast('Enter the decryption key.','err');return;}
  dlBytes(xorBytes(fBytes,key),'decrypted_'+fName.replace(/^encrypted_/,''));
  upd('fStatus','\u2713 Decrypted '+fBytes.length+' bytes \u2014 downloading.');toast('File decrypted and downloading.','ok');
}

/* ── Compare (uses API if online, JS fallback otherwise) ── */
function doCompare(){
  var text=document.getElementById('cmpIn').value.trim();
  var ckey=document.getElementById('cmpKey').value||'Key';
  var sh=((parseInt(document.getElementById('cmpShift').value)||3)%26+26)%26||1;
  if(!text){toast('Enter text to compare.','err');return;}
  function trunc(s,n){return s.length>n?s.substring(0,n)+'\u2026':s;}
  function setCard(id,val,color){var el=document.getElementById('co-'+id);el.textContent=trunc(val,130);el.style.color=color;el.style.fontStyle='normal';document.getElementById('cc-'+id).classList.add('active');}

  var xo=jsXorEnc(text,ckey);
  var co=jsCaesarEnc(text,sh);
  setCard('xor',xo,'var(--gold-d)');
  setCard('caesar',co,'var(--sage-d)');

  if(API_ONLINE){
    apiPost('/api/aes/encrypt',{text:text,key:ckey},function(d){setCard('aes',d.encrypted,'var(--slate)');},function(e){setCard('aes','AES error: '+e,'#b91c1c');});
  } else {
    setCard('aes','Start Python server for AES: python api_server.py','var(--fog)');
  }
  toast('Comparison complete.','ok');
}

/* ── Image export ── */
function setBg(el,bg,fg,accent,theme){
  document.querySelectorAll('.sw').forEach(function(s){s.classList.remove('sel');});
  el.classList.add('sel');iBg=bg;iFg=fg;iAccent=accent||fg;iTheme=theme||'dark';
}
function genImg(){
  var cipher=document.getElementById('imgCipher').value.trim();
  if(!cipher){toast('No cipher text \u2014 encrypt first, or paste here.','err');return;}
  var title=document.getElementById('imgTitle').value||'Encrypted Message';
  var canvas=document.getElementById('imgCanvas'),ctx=canvas.getContext('2d');
  var W=700,pad=30,lh=20;ctx.font='12px monospace';
  var words=cipher.split(' '),lines=[],cur='';
  for(var i=0;i<words.length;i++){var test=cur?cur+' '+words[i]:words[i];if(ctx.measureText(test).width>W-pad*2&&cur){lines.push(cur);cur=words[i];}else cur=test;}
  if(cur)lines.push(cur);
  var H=pad+48+lines.length*lh+pad+28;canvas.width=W;canvas.height=H;
  ctx.fillStyle=iBg;ctx.fillRect(0,0,W,H);
  var dk=iTheme!=='light';
  ctx.fillStyle=dk?'rgba(255,255,255,0.025)':'rgba(0,0,0,0.025)';
  for(var gy=0;gy<H;gy+=16){ctx.fillRect(0,gy,W,.5);}
  ctx.fillStyle=dk?'rgba(255,255,255,0.05)':'rgba(0,0,0,0.035)';ctx.fillRect(0,0,W,44);
  ctx.font='500 13px DM Sans,sans-serif';ctx.fillStyle=iFg;ctx.fillText(title,pad,28);
  var algo=M==='aes'?'AES-256-CBC':M==='caesar'?'Caesar Cipher':'XOR Cipher';
  ctx.font='500 11px DM Mono,monospace';ctx.fillStyle=iAccent;
  ctx.fillText(algo,W-pad-ctx.measureText(algo).width,28);
  ctx.fillStyle=dk?'rgba(255,255,255,0.08)':'rgba(0,0,0,0.07)';ctx.fillRect(pad,44,W-pad*2,.5);
  ctx.font='11.5px DM Mono,monospace';ctx.fillStyle=dk?'rgba(255,255,255,0.52)':'rgba(0,0,0,0.52)';
  for(var li=0;li<lines.length;li++)ctx.fillText(lines[li],pad,66+li*lh);
  ctx.font='10px DM Sans,sans-serif';ctx.fillStyle=dk?'rgba(255,255,255,0.18)':'rgba(0,0,0,0.18)';
  ctx.fillText('CipherLab Pro \u00b7 '+new Date().toLocaleDateString(),pad,H-10);
  document.getElementById('canvasPh').style.display='none';canvas.style.display='block';
  document.getElementById('imgDl').disabled=false;toast('Image generated.','ok');
}
function dlImg(){
  var canvas=document.getElementById('imgCanvas'),a=document.createElement('a');
  a.href=canvas.toDataURL('image/png');
  a.download=(document.getElementById('imgTitle').value||'cipher').replace(/\s+/g,'_')+'_encrypted.png';
  document.body.appendChild(a);a.click();document.body.removeChild(a);toast('PNG downloaded.','info');
}

/* ── Event listeners ── */
document.getElementById('keyInput').addEventListener('input',function(){
  var v=this.value;upd('kLen',v.length+' chars');
  var info=ks(v);var b=document.getElementById('kBdg');b.textContent=info[0];b.className='kb '+info[1];
  var f=document.getElementById('sFill');f.style.width=info[2]+'%';
  f.style.background=info[2]<=20?'#dc2626':info[2]<=60?'var(--gold)':'var(--sage)';
  upd('sK',info[0]);upd('sKs',v.length?v.length+' chars':'not set');
});
document.getElementById('plainIn').addEventListener('input',function(){var n=this.value.length;upd('plainPill',n+' chars');upd('sC',n);});
document.getElementById('shiftInput').addEventListener('input',function(){
  var sh=((parseInt(this.value)||3)%26+26)%26||1;
  document.getElementById('shiftPrev').textContent='A \u2192 '+String.fromCharCode(((65+sh)%26)+65);
  upd('sK','Shift '+sh);upd('sKs','caesar');
});
document.getElementById('visBtn').addEventListener('click',function(){
  kVis=!kVis;document.getElementById('keyInput').type=kVis?'text':'password';
  document.getElementById('eyeSvg').innerHTML=kVis
    ?'<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line>'
    :'<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle>';
});
var fd=document.getElementById('fileDrop');
fd.addEventListener('dragover',function(e){e.preventDefault();fd.classList.add('drag');});
fd.addEventListener('dragleave',function(){fd.classList.remove('drag');});
fd.addEventListener('drop',function(e){
  e.preventDefault();fd.classList.remove('drag');
  var file=e.dataTransfer.files[0];
  if(file){try{var dt=new DataTransfer();dt.items.add(file);document.getElementById('fileIn').files=dt.files;}catch(ex){}loadFile({target:{files:[file]}});}
});

/* ── Init ── */
checkAPI();
