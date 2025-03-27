// Advanced Obfuscated/Minified Code Test with vulnerabilities
// This file contains vulnerable code patterns that are obfuscated or minified

// 1. Obfuscated eval
function _0x4a92(_0x171a,_0x3fb5){const _0x1e87=['eval','parse','log','2523048bLmURU','1013452SgGzcv','9CUthji','308930hKWeQm','1882730MqMhFH','1391616gLGduU','45LTxKUK','6KTnehM','10ymCHOR','test','188090hPJEZd'];_0x4a92=function(){return _0x1e87;};return _0x4a92();}(function(_0x44476d,_0x3ec195){const _0x3a2894=_0x1c68,_0x2bc3d8=_0x44476d();while(!![]){try{const _0x1a2d9c=-parseInt(_0x3a2894(0x1ed))/0x1+-parseInt(_0x3a2894(0x1e5))/0x2*(parseInt(_0x3a2894(0x1e8))/0x3)+parseInt(_0x3a2894(0x1e4))/0x4*(parseInt(_0x3a2894(0x1ea))/0x5)+-parseInt(_0x3a2894(0x1e6))/0x6*(-parseInt(_0x3a2894(0x1ec))/0x7)+parseInt(_0x3a2894(0x1e9))/0x8*(-parseInt(_0x3a2894(0x1ee))/0x9)+parseInt(_0x3a2894(0x1eb))/0xa+parseInt(_0x3a2894(0x1e7))/0xb;if(_0x1a2d9c===_0x3ec195)break;else _0x2bc3d8['push'](_0x2bc3d8['shift']());}catch(_0x15c1d1){_0x2bc3d8['push'](_0x2bc3d8['shift']());}}}(_0x4a92,0xc9d0a));function _0x1c68(_0x171a56,_0x44c83b){const _0x4a92a1=_0x4a92();return _0x1c68=function(_0x1c6888,_0x57e47d){_0x1c6888=_0x1c6888-0x1e4;let _0x5d505c=_0x4a92a1[_0x1c6888];return _0x5d505c;},_0x1c68(_0x171a56,_0x44c83b);}function executeExpression(expr){window['\x65\x76\x61\x6c'](expr);}

// 2. Minified and obfuscated innerHTML
function renderData(a,b){try{const c=document.getElementById(a);if(!c)return!1;setTimeout(function(){const d="ZGF0YQ==";c[(atob(d)=="data"?"inner":"outer")+"HTML"]=b},100)}catch(d){console.error("Error: "+d)}return!0}

// 3. Obfuscated script src injection
const loadScript=function(){var t="script",n=function(r){var e=document.createElement(t);return e.src=r,document.head.appendChild(e),e};return function(r){return n(r)}}();

// 4. Minified postMessage vulnerability
function setupMsgHandler(){window.addEventListener("message",function(e){try{var t=JSON.parse(e.data);t&&t.d&&new Function(atob(t.d))()}catch(r){console.log("Invalid message")}})}

// 5. Minified prototype pollution
function merge(e,r){for(var t in r)r.hasOwnProperty(t)&&("object"==typeof r[t]&&"object"==typeof e[t]?merge(e[t],r[t]):e[t]=r[t]);return e}

// 6. Obfuscated JSON.parse with localStorage
var $jscomp=$jscomp||{};$jscomp.scope={},
function(){var e=localStorage.getItem("user_settings");try{var t=JSON["par"+"se"](e);window.userConfig=t}catch(n){console.error(n)}}();

// 7. Obfuscated DOM XSS with document.write
function showUserContent(data){var _0xf48d=["\x77\x72\x69\x74\x65","\x3C\x64\x69\x76\x20\x63\x6C\x61\x73\x73\x3D\x22\x63\x6F\x6E\x74\x65\x6E\x74\x22\x3E","\x3C\x2F\x64\x69\x76\x3E","\x64\x6F\x63\x75\x6D\x65\x6E\x74"];document[_0xf48d[3]][_0xf48d[0]](_0xf48d[1]+data+_0xf48d[2]);}

// 8. Minified dynamic function creation
function calc(e){return Function("return "+e)()}function processUserFormula(e,r){try{var n=calc(e);return r&&"function"==typeof r?r(n):n}catch(t){return console.error(t),null}}

// 9. Obfuscated DOM property modification
!function(t){const n={st:function(t,n,e){t[n]=e}};t.mod=n}(window);function updateUserBio(t){const n=document.getElementById("bio");window.mod.st(n,"innerHTML",t)}

// 10. Minified and obfuscated XSS with template literals
function tpl(t,n){let e=t,r=/\${(.*?)}/g;return e=e.replace(r,(t,e)=>n[e]||""),document.querySelector(".user-profile").innerHTML=e}

// 11. Minified Function constructor with variable name obfuscation
function o(n,t,c){var a="",i="",u="";return a=n||"",i=t||"",u=c||"",Function(a,i,u)}function p(n){const t=o("a","b","return eval(a+b)");return t(n,"()")}

// 12. Base64 encoded eval
function execCode(code){const decode=str=>Buffer.from(str,'base64').toString('utf-8');return(0,eval)(decode('cmV0dXJuIGV2YWw='))(code)}

// 13. Obfuscated DOM manipulation with direct property assignment
function updateDOM(target,content){const el=document.querySelector(target);if(el){const ops=['in'+'ner'+'HTML','in'+'ner'+'Text'];el[ops[0]]=content}}

// 14. Minified URL manipulation with script creation
function load(t,r){if("string"!=typeof t)return!1;const e=document.createElement("script");e.src=""+t,e.onload=r||null,document.body.appendChild(e)}

// 15. Obfuscated CSP bypass with iframe srcdoc
function createUserFrame(t){const r=document.createElement("iframe");r["sr"+"cd"+"oc"]=t;document.getElementById("user-content").appendChild(r)}