/**
 * TEST SENARYOLARI: Object.prototype Method Testleri
 * Bu test dosyası, Object.prototype'ın güvenli kullanım şekillerinin yanlış pozitif olarak işaretlenmediğini doğrulamak için kullanılır.
 */

// Test 1: Object.prototype.hasOwnProperty.call güvenli kullanımı
function safePropertyCheck(obj, propName) {
  return Object.prototype.hasOwnProperty.call(obj, propName);
}

// Test 2: Güvenli for...in döngüsü
function iterateObjectSafely(obj) {
  for (const key in obj) {
    if (Object.prototype.hasOwnProperty.call(obj, key)) {
      console.log(key, obj[key]);
    }
  }
}

// Test 3: Object.prototype.toString.call ile tip kontrolü
function getTypeOf(value) {
  return Object.prototype.toString.call(value);
}

// Test 4: Object.create(null) kullanımı
function createDictionaryObject() {
  // __proto__ olmayan temiz bir obje oluşturma
  const dict = Object.create(null);
  dict.foo = 'bar';
  return dict;
}

// Test 5: Object.defineProperty güvenli kullanımı
function defineReadOnlyProperty(obj, propName, value) {
  Object.defineProperty(obj, propName, {
    value: value,
    writable: false,
    configurable: false,
    enumerable: true
  });
  return obj;
}

// Test 6: JSON.parse ile prototype pollution engelleme
function safeJsonParse(jsonString) {
  // JSON içinde __proto__ veya constructor kontrolü
  if (typeof jsonString === 'string' && 
      (jsonString.includes('__proto__') || 
       jsonString.includes('constructor') || 
       jsonString.includes('prototype'))) {
    throw new Error('Potential prototype pollution attempt');
  }
  
  return JSON.parse(jsonString);
}

// Test 7: Obje birleştirme işleminde güvenli yöntem
function secureMerge(target, source) {
  // Hedef objeyi klonla
  const result = { ...target };
  
  // Sadece kaynak objenin kendi özellikleri için işlem yap
  for (const key in source) {
    if (Object.prototype.hasOwnProperty.call(source, key)) {
      // __proto__ ve constructor özelliklerini engelle
      if (key !== '__proto__' && key !== 'constructor' && key !== 'prototype') {
        result[key] = source[key];
      }
    }
  }
  
  return result;
}

// Test 8: Object.keys kullanarak güvenli döngü
function processObjectSafely(obj) {
  const keys = Object.keys(obj);
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i];
    console.log(key, obj[key]);
  }
}

// Test 9: Object.getOwnPropertyNames kullanımı
function listAllProperties(obj) {
  return Object.getOwnPropertyNames(obj);
}

// Test 10: Object.freeze ile obje değişmezliği
function createReadOnlyConfig() {
  const config = {
    apiUrl: 'https://api.example.com',
    timeout: 5000,
    retries: 3
  };
  
  return Object.freeze(config);
}