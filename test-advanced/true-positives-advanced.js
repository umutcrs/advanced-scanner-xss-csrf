// Advanced True Positives Test
// This file contains more sophisticated vulnerable patterns that should be detected

// 1. Complex eval pattern with multiple code paths
function complexEvalPattern(expression, userOptions) {
  let result;
  if (userOptions && userOptions.safe) {
    try {
      result = Function('"use strict"; return (' + expression + ')')();
    } catch (e) {
      console.error('Expression evaluation failed:', e);
      result = null;
    }
  } else {
    result = eval('(' + expression + ')'); // Should detect this vulnerable eval
  }
  return result;
}

// 2. HTML sanitization bypass
function sanitizationBypass(html) {
  // Appears to sanitize but actually vulnerable
  html = html.replace(/<script>/gi, '');
  html = html.replace(/<\/script>/gi, '');
  
  const div = document.createElement('div');
  div.innerHTML = html; // Still vulnerable to XSS via other tags
  return div;
}

// 3. Obfuscated innerHTML assignment
function renderUserContent(userId, content) {
  const container = document.getElementById('user-' + userId);
  if (!container) return false;
  
  // Obfuscated innerHTML assignment
  setTimeout(function() {
    const prop = ['inner', 'HTML'].join('');
    container[prop] = content; // Should detect this as innerHTML vulnerability
  }, 100);
}

// 4. Advanced prototype pollution
function deepMergeObjects(target, source) {
  for (const key in source) {
    if (source.hasOwnProperty(key)) {
      if (source[key] && typeof source[key] === 'object') {
        if (!target[key]) target[key] = {};
        deepMergeObjects(target[key], source[key]); // Recursive merge without validation
      } else {
        target[key] = source[key];
      }
    }
  }
  return target; // Vulnerable to prototype pollution
}

// 5. URL manipulation with dynamic protocol
function createDynamicUrl(data) {
  const protocol = data.secure ? 'https' : 'http';
  const url = protocol + '://' + data.domain + '/api?query=' + data.query;
  
  const script = document.createElement('script');
  script.src = url; // Should detect this as vulnerable JSONP/script injection
  document.body.appendChild(script);
}

// 6. Template literal injection
function createDynamicTemplate(user) {
  const template = `
    <div class="user-profile">
      <h2>${user.name}</h2>
      <div class="bio">${user.bio}</div>
      <script>loadUserData(${user.id})</script>
    </div>
  `;
  
  document.getElementById('profile-container').innerHTML = template; // Should detect XSS in template literals
}

// 7. Custom property descriptor with remote data
function setupConfigPropertyDescriptor(config) {
  // Vulnerable approach to setting properties
  Object.defineProperty(window, 'appConfig', {
    value: config,
    writable: false,
    enumerable: true
  });
  
  // Dangerous execution of remote script
  if (config.remoteScript) {
    const script = document.createElement('script');
    script.src = config.remoteScript;
    document.head.appendChild(script); // Should detect script src vulnerability
  }
}

// 8. DOM clobbering vulnerability
function loadUserSettings() {
  // Vulnerable to DOM clobbering
  const settings = window.settings || {};
  const endpoint = settings.apiEndpoint || 'default-api';
  
  // Using clobbered properties in security context
  fetch(endpoint + '/user/profile', {
    credentials: 'include'
  });
}

// 9. Unsafe postMessage handler
function setupMessageListener() {
  window.addEventListener('message', function(event) {
    // No origin checking
    try {
      const data = JSON.parse(event.data);
      if (data.type === 'command') {
        eval(data.payload); // Should detect this as postMessage + eval vulnerability
      }
    } catch (e) {
      console.error('Invalid message format', e);
    }
  });
}

// 10. CSRF vulnerability in form submission
function sendUserData(userData) {
  const form = document.createElement('form');
  form.method = 'POST';
  form.action = '/api/update-profile';
  
  // No CSRF token added to form
  for (const key in userData) {
    const input = document.createElement('input');
    input.type = 'hidden';
    input.name = key;
    input.value = userData[key];
    form.appendChild(input);
  }
  
  document.body.appendChild(form);
  form.submit(); // Should detect CSRF vulnerability
}

// 11. Indirect Command Execution
function processUserCommand(cmd) {
  const execFn = new Function('cmd', 'return eval(cmd)');
  return execFn(cmd); // Should detect this as eval vulnerability
}

// 12. HTML attribute injection
function setUserAvatar(userId, avatarUrl) {
  const img = document.getElementById('user-avatar');
  img.setAttribute('src', avatarUrl); // Potentially vulnerable to XSS via crafted image URLs
  img.setAttribute('onload', 'loadUserProfile(' + userId + ')'); // Should detect event handler injection
}

// 13. Multi-step flow with vulnerable outcome
function initializeUserData(userData) {
  let processedData = {};
  
  try {
    processedData = Object.assign({}, JSON.parse(userData));
    
    if (processedData.preferences) {
      const template = document.querySelector('#preferences-template').innerHTML;
      // Replace placeholders with user data
      const content = template
        .replace('{theme}', processedData.preferences.theme)
        .replace('{language}', processedData.preferences.language);
      
      document.querySelector('#user-preferences').innerHTML = content; // Should detect potential XSS
    }
  } catch (e) {
    console.error('Failed to process user data', e);
  }
}

// 14. Blob URL creation with unsanitized data
function createUserContentBlob(content, type) {
  const blob = new Blob([content], {type: type || 'text/html'});
  const url = URL.createObjectURL(blob);
  
  const iframe = document.createElement('iframe');
  iframe.src = url; // Can lead to XSS if content contains malicious HTML/JS
  document.body.appendChild(iframe);
}

// 15. Mixed content vulnerability
function loadMixedContent(userId) {
  const script = document.createElement('script');
  script.src = 'http://api.example.com/user/' + userId + '/profile.js'; // Mixed content vulnerability (http in https)
  document.body.appendChild(script);
}