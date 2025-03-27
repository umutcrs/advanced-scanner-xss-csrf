/**
 * TEST SENARYOLARI: Minified/Obfuscated Kod Testleri
 * Bu test dosyası, sıkıştırılmış ve karmaşık kodlardaki güvenlik açıklarını tespit etme yeteneğini test eder.
 */

// Test 1: Sıkıştırılmış XSS açığı
const userDisplay=(e,t)=>{const n=document.getElementById(e);n.innerHTML=t};

// Test 2: Sıkıştırılmış eval kullanımı
function execCode(e){return eval(e);}

// Test 3: Kısa adlandırılmış ve sıkıştırılmış postMessage hassasiyeti
const l=(e)=>{window.addEventListener("message",t=>{const n=t.data;console.log(n);e(n)})};

// Test 4: Tek satırda sıkıştırılmış çoklu güvenlik açıkları
const r=(e,t,n)=>{document.write("<div>"+e+"</div>");const o=document.createElement("script");o.src=t;document.body.appendChild(o);eval(n)};

// Test 5: Object destruct içinde gizlenmiş prototype pollution riski
const m=(e,t)=>{const{a,b,...n}=e;const{...o}=t;for(const r in o)n[r]=o[r];return n};

// Test 6: Sıkıştırılmış JSONP callback güvenlik açığı
const fetchJsonP=(e,t)=>{const n=document.createElement("script");n.src=e+"?callback="+t;document.body.appendChild(n)};

// Test 7: Minified iframe srcdoc atama
const embedContent=(e)=>{const t=document.createElement("iframe");t.srcdoc=e;document.body.appendChild(t)};

// Test 8: Sıkıştırılmış URL redirection 
const go=(e)=>{window.location=e};

// Test 9: Sıkıştırılmış outerHTML manipülasyon
const u=(e,t)=>{document.querySelector(e).outerHTML=t};

// Test 10: Obfuscated DOM XSS
function display(a,b){let c="";for(let i=0;i<b.length;i++){c+=String.fromCharCode(b.charCodeAt(i))}document.getElementById(a)[String.fromCharCode(105,110,110,101,114,72,84,77,76)]=c}