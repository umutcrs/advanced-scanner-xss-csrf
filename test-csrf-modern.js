// Modern CSRF Güvenlik Açıkları Test Dosyası
// Bu dosya, CSRF tarayıcısının güncel CSRF açıklarını tespit edip edemediğini test eder

// 1. Zamanlamalı Saldırı için Açık
function insecureCSRFValidation(userCsrfToken, requestCsrfToken) {
    // AÇIK: Sabit zamanlı olmayan karşılaştırma kullanıyor
    if (userCsrfToken === requestCsrfToken) {
        return true;
    }
    return false;
}

// 2. SameSite çerez ayarını atlamak
function setInsecureCookies() {
    // AÇIK: SameSite özelliği olmayan çerezler
    document.cookie = "sessionId=abc123; path=/; secure";
    
    // AÇIK: Hassas verileri içeren çerezler HttpOnly değil
    document.cookie = "authToken=xyz789; path=/";
}

// 3. CSRF Token Tek Kullanımlık Değil
function reuseCSRFToken() {
    // AÇIK: CSRF tokeni yeniden kullanılabilir (geçersiz kılınmıyor)
    const csrfToken = generateRandomToken();
    localStorage.setItem('csrfToken', csrfToken);
    
    // Her istekte aynı token kullanılıyor
    function submitForm() {
        const token = localStorage.getItem('csrfToken');
        fetch('/api/update', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': token
            },
            body: JSON.stringify({ data: 'update-data' })
        });
    }
}

// 4. JWT TokenLeri LocalStorage'da Saklama
function storeTokensInsecurely() {
    // AÇIK: Kimlik doğrulama jetonları localStorage'da saklanıyor
    localStorage.setItem('token', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...');
    localStorage['authToken'] = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...';
    
    // Bu, tokenlerin XSS saldırılarında çalınmasına izin verir
    function getUserData() {
        const token = localStorage.getItem('token');
        return fetch('/api/user', {
            headers: {
                'Authorization': 'Bearer ' + token
            }
        });
    }
}

// 5. Durum Değiştiren GET İstekleri
function stateChangingGetRequests() {
    // AÇIK: Durum değiştiren işlemler için GET kullanımı
    fetch('/api/user/delete?id=123')
        .then(response => console.log('Kullanıcı silindi'));
    
    // Bu, <img> etiketleri veya linkler kullanılarak istismar edilebilir
    // <img src="https://uygulama.com/api/user/delete?id=123" style="display:none">
}

// 6. Dinamik Formlar CSRF Korumasız
function createDynamicFormWithoutProtection() {
    // AÇIK: CSRF token'i olmayan dinamik form oluşturma
    const form = document.createElement('form');
    form.method = 'POST';
    form.action = '/api/settings/update';
    
    const nameInput = document.createElement('input');
    nameInput.name = 'displayName';
    nameInput.value = 'Yeni İsim';
    form.appendChild(nameInput);
    
    // Token olmadan form gönderimi
    document.body.appendChild(form);
    form.submit();
}

// 7. XMLHttpRequest POST CSRF Korumasız
function xhrRequestWithoutCSRFProtection() {
    // AÇIK: CSRF token'i olmayan XHR isteği
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/profile/update', true);
    xhr.withCredentials = true; // Çerezleri gönderir
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.send(JSON.stringify({
        name: 'Yeni İsim',
        email: 'yeni@email.com'
    }));
}

// Yardımcı Fonksiyon
function generateRandomToken() {
    return Math.random().toString(36).substring(2, 15);
}

// Test fonksiyonlarını toplu çalıştır
function runAllTests() {
    console.log("CSRF Güvenlik Testleri Çalıştırılıyor...");
    console.log("NOT: Bu testler sadece tarama amaçlıdır, gerçek güvenlik açıklarına yol açmazlar.");
    
    // Her fonksiyon çalıştırılır (gerçek çalıştırma yoktur, sadece tarama amaçlıdır)
    console.log("Toplam: 7 potansiyel CSRF riski test edildi");
}

// Testleri çalıştır
runAllTests();