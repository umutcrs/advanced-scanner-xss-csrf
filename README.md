# JavaScript Güvenlik Tarayıcısı

![JavaScript Güvenlik Tarayıcısı](generated-icon.png)

JavaScript Güvenlik Tarayıcısı, modern web ve JavaScript uygulamalarındaki güvenlik açıklarını tespit etmek için geliştirilmiş kapsamlı bir statik kod analiz aracıdır. Bu gelişmiş tarayıcı, XSS (Çapraz Site Betikleme) ve CSRF (Siteler Arası İstek Sahteciliği) gibi yaygın güvenlik açıklarını yüksek doğruluk oranıyla tespit eder.

## 🛡️ Özellikler

- **Kapsamlı Güvenlik Taraması**: XSS, CSRF ve diğer yaygın güvenlik açıklarını tespit eder
- **Yüksek Doğruluk Oranı**: Gelişmiş algoritmalar sayesinde false positive oranları minimuma indirilmiştir
- **Detaylı Analiz Raporları**: Bulunan güvenlik açıkları şiddet seviyelerine göre sınıflandırılır
- **Kod İçi Doğrudan Tespitler**: Savunmasız kod satırları ve sütunları doğrudan işaretlenir
- **Düzeltme Önerileri**: Tespit edilen güvenlik açıkları için kod örnekleriyle çözüm önerileri sunar
- **Obfuscated Kod Analizi**: Karmaşıklaştırılmış ve minify edilmiş kodlardaki güvenlik açıklarını tespit eder
- **Çoklu Güvenlik Açığı Kategorileri**: DOM tabanlı, Yansımalı, Depolanan XSS türleri gibi alt kategorilerde analiz sağlar

## 📋 Desteklenen Güvenlik Kontrolleri

### XSS (Çapraz Site Betikleme) Tespiti
- DOM Tabanlı XSS
- Yansımalı XSS
- Depolanan XSS
- innerHTML/outerHTML kötüye kullanımları
- eval() ve dinamik kod yürütme
- Obfuscated/gizlenmiş kodlama teknikleri

### CSRF (Siteler Arası İstek Sahteciliği) Tespiti
- CSRF token eksiklikleri
- Güvenli olmayan form gönderimi
- Kimlik doğrulama sorunları
- Çerez güvenlik yapılandırma eksiklikleri

### Diğer Güvenlik Açıkları
- Prototip Kirlilik (Prototype Pollution)
- Tehlikeli URL kullanımları
- Kaynak Kodu Enjeksiyonu
- Güvensiz JSON işleme
- postMessage güvenlik sorunları
- Tarayıcı eklentisi güvenlik açıkları

## 🎯 Hedef Kullanıcılar

Bu güvenlik tarayıcısı aşağıdaki kullanıcı grupları için ideal çözümler sunar:

### Junior Geliştiriciler (Başlangıç Seviyesi)
- Güvenli kodlama pratiklerini öğrenmek isteyenler
- Kodlamada yaygın güvenlik hatalarını anlamak isteyenler
- Projelerindeki güvenlik açıklarını tespit etmek isteyenler

### Mid-Level Geliştiriciler
- Mevcut kodlarındaki güvenlik zafiyetlerini bulmak isteyenler
- Kod kalitesini ve güvenliğini artırmak isteyenler
- OWASP Top 10 gibi güvenlik standartlarına uyum sağlamak isteyenler

### Senior Geliştiriciler ve Güvenlik Uzmanları
- Karmaşık projelerde derinlemesine güvenlik analizi yapmak isteyenler
- Obfuscated kodlardaki gizli güvenlik açıklarını tespit etmek isteyenler
- CI/CD süreçlerine güvenlik taramalarını entegre etmek isteyenler

### DevOps ve DevSecOps Ekipleri
- Dağıtım öncesi otomatik güvenlik kontrolleri yapmak isteyenler
- Güvenlik açıklarını erken aşamalarda tespit etmek isteyenler

## 🚀 Başlangıç

```bash
# Repoyu klonlayın
git clone https://github.com/kullaniciadi/javascript-guvenlik-tarayicisi.git

# Proje dizinine gidin
cd javascript-guvenlik-tarayicisi

# Bağımlılıkları yükleyin
npm install

# Uygulamayı başlatın
npm run dev
```

## 💡 Nasıl Kullanılır

1. Tarayıcınızda uygulama arayüzüne gidin (varsayılan: `http://localhost:5000`)
2. Taramak istediğiniz JavaScript kodunu metin alanına yapıştırın
3. "Tarama Başlat" düğmesine tıklayın
4. Analiz sonuçlarını ve güvenlik önerilerini inceleyin

## 📊 Örnek Çıktı

```json
{
  "vulnerabilities": [
    {
      "id": "a78c8611-2553-4db1-b4f9-e50d1f0e2a0e",
      "type": "innerHTML",
      "severity": "high",
      "title": "Unsafe innerHTML Assignment",
      "description": "Using innerHTML with user input can lead to XSS vulnerabilities",
      "code": "element.innerHTML = userInput;",
      "line": 5,
      "column": 10,
      "recommendation": "Use textContent instead of innerHTML or sanitize input with DOMPurify"
    }
  ],
  "summary": {
    "critical": 0,
    "high": 1,
    "medium": 0,
    "low": 0,
    "info": 0,
    "total": 1,
    "uniqueTypes": 1,
    "passedChecks": 156
  },
  "scannedAt": "2025-03-27T11:45:19.052Z"
}
```

## 🔧 Geliştiriciler İçin

Bu projeyi geliştirmek veya üzerine katkıda bulunmak isterseniz aşağıdaki adımları izleyebilirsiniz:

1. Repoyu fork edin
2. Yeni bir özellik dalı oluşturun (`git checkout -b yeni-ozellik`)
3. Değişikliklerinizi commit edin (`git commit -am 'Yeni özellik eklendi'`)
4. Dalınızı ana repoya push edin (`git push origin yeni-ozellik`)
5. Pull Request oluşturun

## 📝 Lisans

Bu proje [MIT Lisansı](LICENSE) altında lisanslanmıştır.

## 🙏 Teşekkürler

Bu proje, JavaScript güvenliği konusunda değerli katkılarından dolayı OWASP topluluğuna ve açık kaynak güvenlik araçları geliştiricilerine teşekkür eder.