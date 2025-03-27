/**
 * TEST SENARYOLARI: Gizli Güvenlik Açıkları Testleri
 * Bu test dosyası, iyi yazılmış görünen kod içindeki gizli güvenlik açıklarını tespit etme yeteneğini test eder.
 */

// Test 1: Görünüşte güvenli kod içinde innerHTML kullanımı
function renderUserProfile(userData) {
  // İyi görünen bir fonksiyon, ancak güvenlik açığı var
  validateUserData(userData);
  const profileContainer = document.getElementById('user-profile');
  
  if (profileContainer) {
    // Veri doğrulamasından geçse bile innerHTML kullanımı XSS'e açık
    profileContainer.innerHTML = `
      <div class="profile-header">
        <h2>${userData.name}</h2>
        <p>${userData.bio}</p>
      </div>
    `;
  }
}

// Test 2: İç içe fonksiyonlar arasında gizlenmiş eval kullanımı
function processUserConfiguration(configObject) {
  // Karmaşık bir işlem akışı içinde gizlenmiş eval
  if (!configObject || typeof configObject !== 'object') {
    return null;
  }
  
  function applyAdvancedSettings(settings) {
    if (settings.customLogic && typeof settings.customLogic === 'string') {
      // Gizli eval kullanımı!
      return eval(settings.customLogic);
    }
    return settings;
  }
  
  const userSettings = configObject.settings || {};
  const result = applyAdvancedSettings(userSettings);
  
  return result;
}

// Test 3: Zincirlenmiş metodlar arasında gizlenmiş XSS
function setupUserInterface(userData) {
  return {
    configureLayout: function() {
      return {
        addUserDetails: function() {
          // Zincirlenmiş metodlar içinde gizlenmiş XSS riski
          document.querySelector('.user-container')
                  .getElementsByClassName('details')[0]
                  .innerHTML = userData.details;
        }
      };
    }
  };
}

// Test 4: Şartlı ifadeler içinde gizlenmiş güvensiz redirectler
function navigateToUserPage(userId, options = {}) {
  // Kullanıcı kontrolü ve diğer güvenlik önlemleri
  if (!userId || typeof userId !== 'string') {
    return false;
  }
  
  const baseUrl = '/users/';
  let targetUrl = baseUrl + userId;
  
  // İsteğe bağlı parametreleri ekle
  if (options.returnUrl) {
    // Gizli güvenlik açığı: javascript: URL'lerine izin veriyor
    window.location = options.returnUrl;
    return true;
  } else {
    window.location = targetUrl;
    return true;
  }
}

// Test 5: Try-catch blokları içinde gizlenmiş güvenlik açıkları
function processDynamicTemplate(template, data) {
  try {
    // Kapsamlı kontroller yapılıyor gibi görünüyor
    if (!template || typeof template !== 'string') {
      throw new Error('Invalid template');
    }
    
    // Verinin kontrolü
    if (!data || typeof data !== 'object') {
      throw new Error('Invalid data');
    }
    
    // Gizli XSS: Template içinde string birleştirme
    let processed = template;
    Object.keys(data).forEach(key => {
      processed = processed.replace(`{${key}}`, data[key]);
    });
    
    const element = document.createElement('div');
    // Güvenlik açığı: Doğrulanmamış template içeriği DOM'a ekleniyor
    element.innerHTML = processed;
    return element;
  } catch (e) {
    console.error('Template processing error:', e);
    return null;
  }
}

// Test 6: Callback içinde gizlenmiş güvenlik açığı
function loadUserData(userId, callback) {
  // Normal bir AJAX request fonksiyonu gibi görünüyor
  fetch('/api/users/' + userId)
    .then(response => response.json())
    .then(userData => {
      // Callback içinde güvenlik kontrolü yok
      callback(userData);
    })
    .catch(error => {
      console.error('Error loading user data:', error);
    });
}

// Callback içinde innerHTML kullanımı
function displayUserData(userId) {
  loadUserData(userId, function(userData) {
    // Callback içinde gizlenmiş XSS riski
    document.getElementById('user-container').innerHTML = userData.profileHtml;
  });
}

// Test 7: Karmaşık kontroller içinde gizlenmiş DOM Clobbering riski
function loadConfigFromDOM() {
  // Kapsamlı görünen bir fonksiyon
  function validateConfig(config) {
    return config && typeof config === 'object';
  }
  
  // Gizli DOM Clobbering riski burada
  const config = document.getElementById('app-config') || { settings: defaultSettings };
  
  if (validateConfig(config)) {
    return config;
  }
  
  return { settings: {} };
}

// Test 8: İç içe objeler içinde prototype pollution riski
function deepMerge(target, source) {
  // Düzgün bir derin birleştirme fonksiyonu gibi görünüyor
  if (!source || typeof source !== 'object') return target;
  if (!target || typeof target !== 'object') return source;
  
  for (const key in source) {
    // Güvenli görünüyor ama __proto__ kontrolü yok
    if (typeof source[key] === 'object' && source[key] !== null) {
      target[key] = target[key] || {};
      // Gizli prototype pollution riski
      deepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  
  return target;
}

// Test 9: Geri çağrı fonksiyonları zincirleri içinde gizli güvenlik açıkları
function processFormSubmission(formData) {
  return new Promise((resolve, reject) => {
    validateFormData(formData)
      .then(validatedData => {
        return enrichData(validatedData);
      })
      .then(enrichedData => {
        return saveToDatabase(enrichedData);
      })
      .then(result => {
        // Zincirin en sonunda gizli XSS
        document.getElementById('result-container').innerHTML = 
          `<div class="success">İşlem tamamlandı: ${result.message}</div>`;
        resolve(result);
      })
      .catch(error => {
        reject(error);
      });
  });
}

// Test 10: Korumalı görünen bir fonksiyon içinde gizli URL manipülasyonu
function safeRedirect(url) {
  // Güvenli görünen bir redirect fonksiyonu
  
  // URL formatı kontrolü
  if (!url || typeof url !== 'string') {
    console.error('Invalid URL');
    return false;
  }
  
  // Göreceli URL kontrolü yaptığı için güvenli görünüyor
  if (url.startsWith('http:') || url.startsWith('https:')) {
    const urlObj = new URL(url);
    // Domain kontrolü yapıyor
    if (!allowedDomains.includes(urlObj.hostname)) {
      console.error('Domain not allowed');
      return false;
    }
  }
  
  // Gizli güvenlik açığı: javascript: URL şeması kontrolü eksik
  // javascript:alert(1) gibi bir URL geçerse çalışacak
  window.location = url;
  return true;
}