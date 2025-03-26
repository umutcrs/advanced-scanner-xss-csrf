// UNSAFE: Reflected XSS Örnekleri
// Bu örnekler URL parametrelerini doğrudan DOM'a enjekte eden güvensiz kod parçalarıdır

// Örnek 1: URL parametresini doğrudan innerHTML'e yazma
function displayUserMessage() {
  const urlParams = new URLSearchParams(window.location.search);
  const message = urlParams.get('message');
  document.getElementById('messageBox').innerHTML = message;
}

// Örnek 2: URL hash değerini document.write ile yazma
function displayHashContent() {
  const hashValue = window.location.hash.substring(1);
  document.write('<div>' + hashValue + '</div>');
}

// Örnek 3: QueryString'den veri okuma ve outerHTML ile değiştirme
function updatePageTitle() {
  const urlParams = new URLSearchParams(window.location.search);
  const pageTitle = urlParams.get('title');
  document.getElementById('pageTitle').outerHTML = '<h1>' + pageTitle + '</h1>';
}

// Örnek 4: İç içe DOM manipülasyonu
function updateUserProfile() {
  const userId = new URLSearchParams(window.location.search).get('userId');
  const userName = new URLSearchParams(window.location.search).get('userName');
  
  const userInfo = `
    <div class="user-card">
      <h2>${userName}</h2>
      <p>User ID: ${userId}</p>
    </div>
  `;
  
  document.getElementById('userSection').innerHTML = userInfo;
}

// GÜVENLI: Reflected XSS'e karşı korumalı örnekler
function displayUserMessageSafely() {
  const urlParams = new URLSearchParams(window.location.search);
  const message = urlParams.get('message');
  
  // Seçenek 1: textContent kullanarak
  document.getElementById('messageBox').textContent = message;
  
  // Seçenek 2: DOMPurify ile sanitize edip innerHTML kullanmak
  // import DOMPurify from 'dompurify';
  // document.getElementById('messageBox').innerHTML = DOMPurify.sanitize(message);
}

// Tam URL parametre temizleme örneği
function sanitizeAndDisplayUrlParameter(paramName, elementId) {
  const urlParams = new URLSearchParams(window.location.search);
  let value = urlParams.get(paramName);
  
  if (!value) return;
  
  // 1. HTML karakterlerini escape etme
  value = value
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
  
  // 2. Element içeriğini güvenli şekilde güncelleme
  document.getElementById(elementId).textContent = value;
}