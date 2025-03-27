/**
 * TEST SENARYOLARI: Browser Extension API Testleri
 * Bu test dosyası, tarayıcı eklentilerine özgü güvenli kod desenlerinin yanlış pozitif olarak
 * işaretlenmediğini doğrulamak için kullanılır.
 */

// Test 1: Chrome extension mesaj dinleyicisi
function setupChromeMessageListener() {
  chrome.runtime.onMessage.addListener(function(message, sender, sendResponse) {
    if (message.action === 'getData') {
      sendResponse({status: 'success', data: 'example data'});
    }
    return true; // Keep the message channel open for sendResponse
  });
}

// Test 2: Extension'a özgü postMessage kullanımı
function handleExtensionMessages() {
  window.addEventListener('message', ({ data }) => {
    if (data && data.type === 'FROM_EXTENSION') {
      // Extension'dan gelen mesajları işle
      console.log('Got message from extension:', data.payload);
      
      // Extension'a cevap ver
      window.postMessage({
        type: 'TO_EXTENSION',
        payload: { response: 'Received' }
      }, '*');
    }
  });
}

// Test 3: Chrome extension URL alma
function getExtensionResourceUrl(path) {
  if (chrome && chrome.runtime && chrome.runtime.getURL) {
    return chrome.runtime.getURL(path);
  }
  return null;
}

// Test 4: Content script mesaj gönderici
function sendMessageToBackgroundScript(data) {
  if (chrome && chrome.runtime) {
    chrome.runtime.sendMessage(data, function(response) {
      console.log('Background script response:', response);
    });
  }
}

// Test 5: Web sayfası ve extension arasında mesajlaşma
const onMessage = ({ data }) => {
  if (!data.extAPI) return;
  
  // İşlem tamamlandığında dinleyiciyi kaldır
  removeEventListener('message', onMessage);
  
  // Extension API'a cevap ver
  postMessage({ extAPI: { result: 'success' } });
};

addEventListener('message', onMessage);

// Test 6: Tab mesajlaşma 
function sendMessageToTab(tabId, message) {
  chrome.tabs.sendMessage(tabId, message, function(response) {
    console.log('Tab response:', response);
  });
}

// Test 7: Background script setup
function setupBackgroundListeners() {
  chrome.runtime.onInstalled.addListener(function(details) {
    console.log('Extension installed:', details.reason);
  });
  
  chrome.browserAction.onClicked.addListener(function(tab) {
    chrome.tabs.create({ url: 'dashboard.html' });
  });
}

// Test 8: Content script enjeksiyonu
function injectDynamicContentScript(tabId, code) {
  chrome.tabs.executeScript(tabId, { code: code }, function(result) {
    console.log('Script injection result:', result);
  });
}

// Test 9: Extension storage API kullanımı
function saveToExtensionStorage(key, value) {
  chrome.storage.sync.set({ [key]: value }, function() {
    console.log('Data saved to extension storage');
  });
}

// Test 10: Extension'a özgü DOM manipülasyonu
function setupExtensionUI() {
  document.addEventListener('DOMContentLoaded', function() {
    const button = document.getElementById('action-button');
    button.addEventListener('click', function() {
      chrome.runtime.sendMessage({ action: 'buttonClicked' });
    });
  });
}