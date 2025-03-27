/**
 * TEST SENARYOLARI: True Positive Testleri
 * Bu test dosyası, güvenlik açığı içeren kodların başarıyla tespit edilmesini test eder.
 */

// Test 1: innerHTML kullanımı - XSS riski
function displayUserProfile(userProfile) {
  // İşlenmemiş kullanıcı verisi doğrudan DOM'a enjekte ediliyor - Ciddi XSS riski
  document.getElementById('profile-container').innerHTML = userProfile;
}

// Test 2: eval kullanımı - Kod enjeksiyonu riski
function calculateUserExpression(expression) {
  // Kullanıcı girdisinin eval ile çalıştırılması - Ciddi kod yürütme riski
  return eval(expression);
}

// Test 3: document.write - XSS riski
function updatePageContent(content) {
  // document.write kullanımı - XSS riski
  document.write('<div>' + content + '</div>');
}

// Test 4: Güvensiz iframe src atama
function loadExternalContent(url) {
  // URL doğrulaması olmadan iframe kaynağı atama
  const iframe = document.createElement('iframe');
  iframe.src = url; // Doğrulama olmadan kaynak atama
  document.body.appendChild(iframe);
}

// Test 5: Olay işleyici atribütü - XSS riski
function setupClickHandler(handler) {
  // Kullanıcı girdisi doğrudan olay işleyicisi olarak atanıyor
  const button = document.getElementById('action-button');
  button.setAttribute('onclick', handler); // Güvensiz olay işleyici ataması
}

// Test 6: Güvensiz postMessage kullanımı
function setupMessageReceiver() {
  // Origin kontrolü olmadan mesaj dinleme
  window.addEventListener('message', function(event) {
    // Köken doğrulaması yapılmıyor!
    processMessage(event.data);
  });
}

// Test 7: Güvensiz JSON.parse kullanımı
function parseUserJsonInput(jsonInput) {
  // Doğrulama olmadan JSON parse etme
  return JSON.parse(jsonInput);
}

// Test 8: CSRF koruması olmayan form
function createUserForm(userName, userEmail) {
  // CSRF token içermeyen form
  return `
    <form action="/update-profile" method="POST">
      <input type="text" name="name" value="${userName}">
      <input type="email" name="email" value="${userEmail}">
      <button type="submit">Güncelle</button>
    </form>
  `;
}

// Test 9: Güvensiz dinamik script oluşturma
function loadExternalScript(scriptUrl) {
  // Doğrulama olmadan harici script yükleme
  const script = document.createElement('script');
  script.src = scriptUrl;
  document.head.appendChild(script);
}

// Test 10: Protokol doğrulaması olmayan URL redirectleri
function redirectUser(redirectUrl) {
  // Protokol doğrulaması olmadan yönlendirme - javascript: protokolü riski
  window.location = redirectUrl;
}

// Test 11: Prototype pollution riski
function mergeObjects(target, source) {
  // Özel anahtarların kontrolü olmadan obje birleştirme
  for (let key in source) {
    target[key] = source[key];
  }
  return target;
}

// Test 12: outerHTML kullanımı - XSS riski
function replaceUserContent(element, content) {
  // Güvensiz outerHTML kullanımı
  element.outerHTML = content;
}

// Test 13: Güvensiz DOMParser kullanımı
function parseHtmlContent(htmlContent) {
  // Doğrulama olmadan HTML içeriği ayrıştırma
  const parser = new DOMParser();
  return parser.parseFromString(htmlContent, 'text/html');
}

// Test 14: Güvensiz setInterval kullanımı
function setupIntervalWithCodeString(codeString, interval) {
  // String olarak kod çalıştırma
  setInterval(codeString, interval);
}

// Test 15: Template literal ile HTML oluşturma - XSS riski
function createUserCard(userData) {
  // Template literal ile güvensiz HTML oluşturma
  const cardHTML = `
    <div class="user-card">
      <h3>${userData.name}</h3>
      <div class="description">${userData.description}</div>
    </div>
  `;
  document.getElementById('user-container').innerHTML = cardHTML;
}