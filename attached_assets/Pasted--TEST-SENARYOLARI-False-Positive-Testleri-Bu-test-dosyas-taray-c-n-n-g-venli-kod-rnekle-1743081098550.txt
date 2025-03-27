/**
 * TEST SENARYOLARI: False Positive Testleri
 * Bu test dosyası, tarayıcının güvenli kod örneklerini yanlış pozitif 
 * olarak işaretlemediğini doğrulamak için kullanılır.
 */

// Test 1: Object.prototype.hasOwnProperty.call - Güvenli kod
function securePropertyCheck(obj, prop) {
  // Bu güvenli bir Object mülkiyet kontrolü yapısıdır
  return Object.prototype.hasOwnProperty.call(obj, prop);
}

// Test 2: DOMPurify kullanımı - Güvenli kod
function purifyHtml(unsafeHtml) {
  // XSS koruması için DOMPurify kullanımı
  return DOMPurify.sanitize(unsafeHtml);
}

// Test 3: textContent kullanımı - Güvenli kod
function displayUserName(name) {
  const element = document.getElementById('user-name');
  element.textContent = name;
  return element;
}

// Test 4: Encoded URL parametreleri - Güvenli kod
function createSafeUrl(baseUrl, params) {
  const url = new URL(baseUrl);
  
  // Parametreleri güvenli bir şekilde ekle
  Object.keys(params).forEach(key => {
    url.searchParams.append(key, encodeURIComponent(params[key]));
  });
  
  return url.toString();
}

// Test 5: JSON.parse güvenli kullanımı
function safeParseJson(jsonStr) {
  try {
    // İyi bir hata yakalama örneği
    return JSON.parse(jsonStr);
  } catch (e) {
    console.error("Invalid JSON format", e);
    return null;
  }
}

// Test 6: addEventListener'ın güvenli kullanımı
function setupEventListener() {
  document.getElementById('button').addEventListener('click', function(event) {
    // Olay işleyicisi, doğrudan fonksiyon referansı olarak geçirildi
    console.log('Button clicked!');
  });
}

// Test 7: Güvenli iframe kaynağı doğrulama
function createSafeIframe(url) {
  // URL protokol kontrolü
  if (!/^https:\/\//.test(url)) {
    console.error("Only HTTPS URLs are allowed");
    return null;
  }
  
  // Güvenli alan kontrolü
  const trustedDomains = ['example.com', 'trusted-site.com'];
  const urlObj = new URL(url);
  
  if (!trustedDomains.some(domain => urlObj.hostname === domain || urlObj.hostname.endsWith('.' + domain))) {
    console.error("Domain not in trusted list");
    return null;
  }
  
  const iframe = document.createElement('iframe');
  iframe.src = url;
  iframe.sandbox = 'allow-scripts allow-same-origin'; // Sandbox ekleme
  
  return iframe;
}

// Test 8: fetch API ile güvenlik kotrolü
async function fetchWithCSRFProtection(url, method = 'GET', data = null) {
  const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
  
  const options = {
    method,
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': csrfToken
    },
    credentials: 'same-origin'
  };
  
  if (data && method !== 'GET') {
    options.body = JSON.stringify(data);
  }
  
  return fetch(url, options);
}

// Test 9: Özel elementler oluşturma - Güvenli kullanım
function createCustomElement(tagName, content) {
  // Sadece izin verilen elementleri oluştur
  const allowedTags = ['div', 'span', 'p', 'h1', 'h2', 'h3', 'ul', 'li'];
  
  if (!allowedTags.includes(tagName)) {
    console.error("Tag not allowed:", tagName);
    return null;
  }
  
  const element = document.createElement(tagName);
  element.textContent = content; // innerHTML yerine textContent kullanımı
  
  return element;
}

// Test 10: Template literal - Güvenli String birleştirme
function safeTemplateUsage(userName) {
  // Template literal güvenli kullanımı
  const greeting = `Merhaba ${userName}, hoş geldiniz!`;
  document.getElementById('greeting').textContent = greeting;
}

// Test 11: Browser extension API güvenli kullanımı
function chromeExtensionSafeCode() {
  if (typeof chrome !== 'undefined' && chrome.runtime) {
    chrome.runtime.sendMessage({action: 'getData'}, function(response) {
      console.log('Received data:', response);
    });
  }
}

// Test 12: postMessage güvenli kullanımı
function setupSecureMessageListener() {
  window.addEventListener('message', function(event) {
    // Origin kontrolü
    if (event.origin !== 'https://trusted-site.com') {
      console.error('Message received from untrusted origin:', event.origin);
      return;
    }
    
    // Veri kontrolünden sonra işleme
    console.log('Received secure message:', event.data);
  });
}