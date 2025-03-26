// UNSAFE: DOM-based XSS Örnekleri
// Bu örnekler DOM kaynaklarından alınan verileri doğrudan DOM'a enjekte eden güvensiz kod parçalarıdır

// Örnek 1: URL hash parametresini doğrudan innerHTML'e yazma
function displayHashContent() {
  const hashData = document.location.hash.substring(1); // Başındaki # işaretini kaldırır
  document.getElementById('contentArea').innerHTML = hashData;
}

// Örnek 2: document.referrer kullanımı
function showReferrer() {
  const referrer = document.referrer;
  document.getElementById('referrerDisplay').innerHTML = `Referrer: ${referrer}`;
}

// Örnek 3: URL parametrelerini doğrudan DOM'a yazma
function updatePageFromUrl() {
  const urlObj = new URL(document.URL);
  const theme = urlObj.searchParams.get('theme');
  const content = urlObj.searchParams.get('content');
  
  // Tema uygulaması
  document.getElementById('themeContainer').innerHTML = `<div class="${theme}">Tema uygulandı</div>`;
  
  // İçerik güncellemesi
  document.getElementById('dynamicContent').innerHTML = content;
}

// Örnek 4: DOM fragmentlerini dinamik olarak işleme
function handleFragmentNavigation() {
  const fragment = window.location.hash;
  let content = '';
  
  if (fragment === '#home') {
    content = '<h1>Ana Sayfa</h1><p>Hoş geldiniz!</p>';
  } else if (fragment === '#profile') {
    content = '<h1>Profil Sayfası</h1><p>Profil içeriği buraya gelecek</p>';
  } else if (fragment === '#settings') {
    content = '<h1>Ayarlar</h1><p>Ayarlar içeriği</p>';
  } else {
    // Tehlikeli - user-controlled fragmentler
    content = `<h1>${fragment.substring(1)}</h1><p>Sayfa bulunamadı</p>`;
  }
  
  document.getElementById('pageContent').innerHTML = content;
}

// Örnek 5: document.cookie değerlerini kullanma
function displayCookieInfo() {
  const cookieValue = document.cookie;
  document.getElementById('cookieDisplay').innerHTML = `Cookies: ${cookieValue}`;
}

// GÜVENLI: DOM-based XSS'e karşı korumalı örnekler
function displayHashContentSafely() {
  const hashData = document.location.hash.substring(1); 
  
  // Seçenek 1: textContent kullanarak
  document.getElementById('contentArea').textContent = hashData;
}

// DOM kaynaklarından alınan verileri DOMPurify ile güvenli hale getirme
function sanitizeAndDisplayDOMSource() {
  // import DOMPurify from 'dompurify';
  
  // URL hash'inden veri alma
  const hashData = document.location.hash.substring(1);
  
  // Veriyi sanitize etme
  const sanitizedData = DOMPurify.sanitize(hashData);
  
  // Güvenli bir şekilde DOM'a ekleme
  document.getElementById('contentArea').innerHTML = sanitizedData;
}

// Güvenli fragment yönlendirmesi
function safeFragmentNavigation() {
  const fragment = window.location.hash.slice(1); // # işaretini çıkar
  
  // İzin verilen fragmentlerin listesi
  const allowedFragments = ['home', 'profile', 'settings', 'help', 'contact'];
  
  if (allowedFragments.includes(fragment)) {
    // Güvenli bir fragment, bu sayfayı göster
    showPage(fragment);
  } else {
    // Bilinmeyen fragment, varsayılan sayfayı göster
    showPage('home');
  }
}

// Yardımcı fonksiyon - sayfaları güvenli şekilde gösterme
function showPage(page) {
  // Tüm sayfa içeriklerini gizle
  const allPages = document.querySelectorAll('.page-content');
  allPages.forEach(pageElement => {
    pageElement.style.display = 'none';
  });
  
  // Sadece istenen sayfayı göster
  const selectedPage = document.getElementById(`${page}-page`);
  if (selectedPage) {
    selectedPage.style.display = 'block';
  }
}