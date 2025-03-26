// UNSAFE: Stored XSS Örnekleri
// Bu örnekler depolanan verileri doğrudan DOM'a enjekte eden güvensiz kod parçalarıdır

// Örnek 1: localStorage'dan doğrudan innerHTML'e veri yazma
function loadUserProfile() {
  const userData = JSON.parse(localStorage.getItem('userData'));
  if (userData) {
    document.getElementById('userBio').innerHTML = userData.bio;
    document.getElementById('userName').innerHTML = userData.name;
  }
}

// Örnek 2: API'den gelen verileri doğrudan DOM'a enjekte etme
async function loadComments() {
  const response = await fetch('/api/comments');
  const comments = await response.json();
  
  let commentHTML = '';
  comments.forEach(comment => {
    commentHTML += `<div class="comment">
      <h3>${comment.author}</h3>
      <p>${comment.text}</p>
    </div>`;
  });
  
  document.getElementById('commentSection').innerHTML = commentHTML;
}

// Örnek 3: IndexedDB'den veri yükleme ve DOM'a ekleme
function loadUserData(userId) {
  const request = indexedDB.open('userDB', 1);
  
  request.onsuccess = function(event) {
    const db = event.target.result;
    const transaction = db.transaction(['users'], 'readonly');
    const objectStore = transaction.objectStore('users');
    const userRequest = objectStore.get(userId);
    
    userRequest.onsuccess = function(event) {
      const userData = event.target.result;
      if (userData) {
        document.getElementById('userProfile').innerHTML = `
          <div class="profile-header">
            <h2>${userData.name}</h2>
            <p>${userData.status}</p>
          </div>
          <div class="profile-content">${userData.content}</div>
        `;
      }
    };
  };
}

// Örnek 4: SessionStorage kullanımı
function restoreFormState() {
  const formData = JSON.parse(sessionStorage.getItem('formState'));
  if (formData) {
    document.getElementById('savedContent').innerHTML = formData.content;
  }
}

// GÜVENLI: Stored XSS'e karşı korumalı örnekler
function loadUserProfileSafely() {
  try {
    const userData = JSON.parse(localStorage.getItem('userData'));
    if (userData) {
      // Metin içeriği güvenli şekilde ekleme
      document.getElementById('userBio').textContent = userData.bio;
      document.getElementById('userName').textContent = userData.name;
    }
  } catch (error) {
    console.error('User data parsing error:', error);
  }
}

// API verilerini güvenli şekilde işleme
async function loadCommentsSafely() {
  try {
    const response = await fetch('/api/comments');
    const comments = await response.json();
    
    const commentSection = document.getElementById('commentSection');
    // Önce mevcut içeriği temizle
    commentSection.innerHTML = '';
    
    comments.forEach(comment => {
      // Her yorum için yeni DOM elementleri oluştur
      const commentDiv = document.createElement('div');
      commentDiv.className = 'comment';
      
      const authorHeading = document.createElement('h3');
      authorHeading.textContent = comment.author;
      
      const commentText = document.createElement('p');
      commentText.textContent = comment.text;
      
      // DOM'a güvenli şekilde ekle
      commentDiv.appendChild(authorHeading);
      commentDiv.appendChild(commentText);
      commentSection.appendChild(commentDiv);
    });
  } catch (error) {
    console.error('Comment loading error:', error);
  }
}

// DOMPurify ile içerik sanitize etme örneği
function sanitizeAndDisplayStoredContent() {
  // import DOMPurify from 'dompurify';
  
  const storedHTML = localStorage.getItem('formattedContent');
  if (storedHTML) {
    // HTML içeriği sanitize et ve sonra göster
    const cleanHTML = DOMPurify.sanitize(storedHTML);
    document.getElementById('contentDisplay').innerHTML = cleanHTML;
  }
}