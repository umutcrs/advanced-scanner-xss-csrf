// Browser Extension Security Patterns (Safe and Unsafe)
// This file contains a mix of safe and unsafe patterns specific to browser extensions

// SECTION 1: UNSAFE PATTERNS

// 1. Unsafe message passing without origin validation
function unsafeMessageListener() {
  chrome.runtime.onMessage.addListener(function(message, sender, sendResponse) {
    // No sender validation
    if (message.action === 'executeScript') {
      eval(message.code); // Critical: Executing arbitrary code from messages
    }
    sendResponse({status: 'completed'});
  });
}

// 2. Unsafe content script injection
function injectDynamicContentScript(tabId, userScript) {
  chrome.scripting.executeScript({
    target: {tabId: tabId},
    func: function(scriptToRun) {
      // Injecting and executing user-provided code
      eval(scriptToRun); // Critical: Executing arbitrary code
    },
    args: [userScript]
  });
}

// 3. Unsafe extension storage usage
function storeUserDataUnsafe(userData) {
  // Storing unsanitized user data
  chrome.storage.sync.set({
    'userData': userData,
    'userScript': userData.customScript
  }, function() {
    console.log('User data saved');
    
    // Later used unsafely
    chrome.storage.sync.get(['userScript'], function(result) {
      if (result.userScript) {
        eval(result.userScript); // Critical: Executing code from storage
      }
    });
  });
}

// 4. Unsafe use of tabs.executeScript (Manifest V2)
function executeUnsafeScript(tabId, code) {
  chrome.tabs.executeScript(tabId, {
    code: code // Critical: Directly executing user-provided code
  });
}

// 5. Unsafe external content loading
function loadExternalScriptUnsafe(url) {
  fetch(url)
    .then(response => response.text())
    .then(code => {
      // Critical: Executing code from external source
      chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        chrome.tabs.executeScript(tabs[0].id, {code: code});
      });
    });
}

// 6. Using user input for origin in postMessage
function sendUnsafePostMessage(message, targetOrigin) {
  // Critical: Using user-controlled targetOrigin
  window.postMessage(message, targetOrigin || '*');
}

// 7. Insecure handling of web accessible resources
function getUnsafeResourceUrl(resourceName, userId) {
  const url = chrome.runtime.getURL(resourceName);
  return url + '?user=' + userId; // Adding user data to URL that could be accessed by websites
}

// 8. Injection through dynamic imports
async function loadDynamicModuleUnsafe(modulePath) {
  try {
    // Critical: Loading dynamic modules from user input
    const module = await import(modulePath);
    module.initialize();
  } catch (error) {
    console.error('Failed to load module', error);
  }
}

// 9. Unsafe content security policy
function modifyCSPUnsafe(details) {
  // Critical: Weakening CSP
  const cspHeaders = details.responseHeaders.filter(header => 
    header.name.toLowerCase() === 'content-security-policy'
  );
  
  if (cspHeaders.length > 0) {
    // Removing CSP restrictions
    cspHeaders[0].value = cspHeaders[0].value
      .replace("'unsafe-eval'", "")
      .replace("script-src", "script-src 'unsafe-eval' http: https:");
  }
  
  return {responseHeaders: details.responseHeaders};
}

// 10. Vulnerable external message handling
function setupExternalMessageListener() {
  // Critical: Accepting external messages without proper validation
  chrome.runtime.onMessageExternal.addListener(
    function(request, sender, sendResponse) {
      // Executing actions based on external requests without validation
      if (request.action === 'updateSettings') {
        chrome.storage.sync.set({'settings': request.settings});
      }
      sendResponse({status: 'success'});
    }
  );
}

// SECTION 2: SAFE PATTERNS

// 1. Safe message passing with origin and sender validation
function safeMessageListener() {
  chrome.runtime.onMessage.addListener(function(message, sender, sendResponse) {
    // Validate sender is from our extension
    if (!sender.id || sender.id !== chrome.runtime.id) {
      console.error('Message from unauthorized source rejected');
      return false;
    }
    
    // Validate message structure
    if (!message || typeof message !== 'object' || !message.action) {
      console.error('Invalid message format');
      return false;
    }
    
    // Use a switch with specific allowed actions
    switch (message.action) {
      case 'getData':
        sendResponse({data: getSafeData()});
        break;
      case 'updateUI':
        updateUIElements(message.elements);
        sendResponse({status: 'UI updated'});
        break;
      default:
        console.error('Unknown action requested:', message.action);
        sendResponse({error: 'Unsupported action'});
    }
    
    return true; // Keep the message channel open for async response
  });
}

// 2. Safe content script injection
function injectSafeContentScript(tabId) {
  // Use predefined scripts from extension resources
  chrome.scripting.executeScript({
    target: {tabId: tabId},
    files: ['content-scripts/safe-script.js'] // Predefined extension script
  });
}

// 3. Safe extension storage usage
function storeUserDataSafe(userData) {
  // Validate and sanitize before storage
  const sanitizedData = sanitizeUserData(userData);
  
  chrome.storage.sync.set({
    'userData': sanitizedData
  }, function() {
    console.log('Sanitized user data saved');
  });
}

// Sanitization helper function
function sanitizeUserData(data) {
  const sanitized = {};
  
  // Whitelist approach for specific fields
  if (data.name && typeof data.name === 'string') {
    sanitized.name = data.name.substring(0, 100); // Limit length
  }
  
  if (data.preferences && typeof data.preferences === 'object') {
    sanitized.preferences = {};
    
    // Whitelist specific preference fields
    const allowedPrefs = ['theme', 'fontSize', 'notifications'];
    for (const pref of allowedPrefs) {
      if (typeof data.preferences[pref] !== 'undefined') {
        sanitized.preferences[pref] = data.preferences[pref];
      }
    }
  }
  
  return sanitized;
}

// 4. Safe use of scripting API (Manifest V3)
function executeSafeScript(tabId) {
  // Using predefined function with no user input
  chrome.scripting.executeScript({
    target: {tabId: tabId},
    func: function() {
      // Predefined code that runs in page context
      document.body.style.backgroundColor = 'lightblue';
    }
  });
}

// 5. Safe external content loading with validation
async function loadExternalScriptSafe(url) {
  // Validate URL against whitelist
  const allowedDomains = [
    'trusted-cdn.example.com',
    'extension-resources.example.org'
  ];
  
  try {
    const urlObj = new URL(url);
    
    if (!allowedDomains.includes(urlObj.hostname)) {
      throw new Error('Domain not in whitelist');
    }
    
    // Fetch content with integrity checks when possible
    const response = await fetch(url);
    const code = await response.text();
    
    // Instead of executing, use for non-executable purposes
    // or run through a content security validator
    displayScriptContents(code);
  } catch (error) {
    console.error('Failed to load external content safely:', error);
  }
}

// 6. Safe postMessage with specific origin
function sendSafePostMessage(message, allowedOrigin) {
  // Whitelist of allowed origins
  const trustedOrigins = [
    'https://example.com',
    'https://trusted-app.example.org'
  ];
  
  // Validate target origin
  if (!trustedOrigins.includes(allowedOrigin)) {
    console.error('Untrusted target origin rejected:', allowedOrigin);
    return false;
  }
  
  // Safe postMessage with specific origin
  window.postMessage(message, allowedOrigin);
  return true;
}

// 7. Secure handling of web accessible resources
function getSafeResourceUrl(resourceName) {
  // Only return URLs for whitelisted resources
  const allowedResources = [
    'images/icon.png',
    'styles/theme.css',
    'scripts/public-api.js'
  ];
  
  if (!allowedResources.includes(resourceName)) {
    console.error('Requested resource is not web accessible:', resourceName);
    return null;
  }
  
  return chrome.runtime.getURL(resourceName);
}

// 8. Safe dynamic imports with validation
async function loadDynamicModuleSafe(moduleName) {
  // Whitelist of allowed modules
  const allowedModules = {
    'analytics': './modules/analytics.js',
    'ui': './modules/ui.js',
    'storage': './modules/storage.js'
  };
  
  if (!allowedModules[moduleName]) {
    console.error('Module not in allowed list:', moduleName);
    return null;
  }
  
  try {
    // Load from predefined path, not user input
    const module = await import(allowedModules[moduleName]);
    return module;
  } catch (error) {
    console.error('Failed to load module', error);
    return null;
  }
}

// 9. Safe content security policy handling
function enhanceCSP(details) {
  const cspHeaders = details.responseHeaders.filter(header => 
    header.name.toLowerCase() === 'content-security-policy'
  );
  
  if (cspHeaders.length > 0) {
    // Strengthen CSP, not weaken it
    let csp = cspHeaders[0].value;
    
    // Ensure unsafe-eval is not allowed
    if (!csp.includes("'unsafe-eval'")) {
      // Good, don't add it
    } else {
      // Remove unsafe-eval
      csp = csp.replace("'unsafe-eval'", "");
    }
    
    // Update the header
    cspHeaders[0].value = csp;
  } else {
    // Add a CSP header if none exists
    details.responseHeaders.push({
      name: 'Content-Security-Policy',
      value: "default-src 'self'; script-src 'self'; object-src 'none'"
    });
  }
  
  return {responseHeaders: details.responseHeaders};
}

// 10. Safe external message handling
function setupSafeExternalMessageListener() {
  // Whitelist of trusted extension IDs
  const trustedExtensions = [
    'abcdefghijklmnopqrstuvwxyzabcdef', // Example trusted extension ID
    'fedcbazyxwvutsrqponmlkjihgfedcba'  // Another trusted extension
  ];
  
  chrome.runtime.onMessageExternal.addListener(
    function(request, sender, sendResponse) {
      // Validate sender
      if (!sender.id || !trustedExtensions.includes(sender.id)) {
        console.error('Message from unauthorized extension rejected:', sender.id);
        sendResponse({error: 'Unauthorized'});
        return false;
      }
      
      // Validate message format
      if (!request || typeof request !== 'object' || !request.action) {
        sendResponse({error: 'Invalid request format'});
        return false;
      }
      
      // Process only allowed actions with proper validation
      if (request.action === 'getData') {
        // Return only allowed data
        sendResponse({
          version: chrome.runtime.getManifest().version,
          publicData: getPublicExtensionData()
        });
      } else {
        sendResponse({error: 'Action not supported'});
      }
      
      return true;
    }
  );
}

// Helper functions for safe patterns
function updateUIElements(elements) {
  // Safe UI updates
}

function getSafeData() {
  // Return safely sanitized data
  return { version: "1.0.0", timestamp: Date.now() };
}

function displayScriptContents(code) {
  // Display, don't execute
  const el = document.getElementById('script-viewer');
  if (el) {
    el.textContent = code;
  }
}

function getPublicExtensionData() {
  // Return only public data safe for external consumption
  return {
    name: chrome.runtime.getManifest().name,
    version: chrome.runtime.getManifest().version,
    publicAPI: {
      supportedActions: ['getData', 'showNotification']
    }
  };
}