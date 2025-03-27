// Advanced False Positives Test
// This file contains sophisticated safe patterns that should NOT be detected as vulnerabilities

// 1. Safe JSON parsing with validation
function safeJsonParseAdvanced(jsonString, schema) {
  // Type check
  if (typeof jsonString !== 'string') {
    throw new TypeError('Expected string input for JSON parsing');
  }
  
  // Format validation
  if (!jsonString.trim().match(/^[{\[].*[}\]]$/)) {
    throw new Error('Invalid JSON format');
  }
  
  // Check for suspicious patterns
  if (/__(proto|defineGetter|defineSetter|lookupGetter|lookupSetter)__/.test(jsonString)) {
    throw new Error('Potentially malicious JSON detected');
  }
  
  try {
    // Parse with try/catch
    const parsed = JSON.parse(jsonString);
    
    // Schema validation (if provided)
    if (schema && typeof schema === 'object') {
      validateAgainstSchema(parsed, schema);
    }
    
    return parsed;
  } catch (error) {
    console.error('JSON parsing failed:', error);
    return null;
  }
}

// 2. Properly sanitized HTML insertion
function renderSanitizedHtml(unsafeHtml, container) {
  // Import sanitizer library (assumed to be available)
  const DOMPurify = window.DOMPurify;
  
  if (!DOMPurify) {
    throw new Error('DOMPurify is required for HTML sanitization');
  }
  
  // Configure sanitizer with strict settings
  const sanitizerConfig = {
    ALLOWED_TAGS: ['p', 'b', 'i', 'em', 'strong', 'a', 'ul', 'ol', 'li', 'span', 'div'],
    ALLOWED_ATTR: ['href', 'class', 'id', 'target'],
    FORBID_TAGS: ['script', 'style', 'iframe', 'object', 'embed'],
    FORBID_ATTR: ['onerror', 'onload', 'onclick', 'onmouseover'],
    ALLOW_DATA_ATTR: false,
    USE_PROFILES: {html: true}
  };
  
  // Sanitize HTML
  const sanitized = DOMPurify.sanitize(unsafeHtml, sanitizerConfig);
  
  // Safe DOM insertion
  if (container && container instanceof HTMLElement) {
    container.innerHTML = sanitized;
  }
  
  return sanitized;
}

// 3. Safe property descriptor usage
function createSafePropertyDescriptor(obj, allowedProperties) {
  // Whitelist approach for property names
  const safeDescriptors = {};
  
  Object.keys(allowedProperties).forEach(key => {
    // Prevent risky property names
    if (key === '__proto__' || 
        key === 'constructor' || 
        key === 'prototype') {
      console.warn(`Skipping unsafe property name: ${key}`);
      return;
    }
    
    // Create safe descriptor
    Object.defineProperty(obj, key, {
      value: allowedProperties[key],
      writable: false,
      enumerable: true,
      configurable: false
    });
    
    safeDescriptors[key] = allowedProperties[key];
  });
  
  return safeDescriptors;
}

// 4. Safe object merging without prototype pollution
function safeMergeDeep(target, source) {
  const output = Object.assign({}, target);
  
  if (isObject(target) && isObject(source)) {
    Object.keys(source).forEach(key => {
      // Skip prototype properties
      if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
        console.warn(`Skipping unsafe property: ${key}`);
        return;
      }
      
      if (isObject(source[key])) {
        if (!(key in target)) {
          Object.assign(output, { [key]: source[key] });
        } else {
          output[key] = safeMergeDeep(target[key], source[key]);
        }
      } else {
        Object.assign(output, { [key]: source[key] });
      }
    });
  }
  
  return output;
}

// Helper function for type checking
function isObject(item) {
  return (item && typeof item === 'object' && !Array.isArray(item));
}

// 5. Safe DOM element creation
function createSafeElement(tagName, content, attributes) {
  // Validate tag name against whitelist
  const allowedTags = ['div', 'span', 'p', 'a', 'button', 'h1', 'h2', 'h3', 'ul', 'ol', 'li', 'input', 'label'];
  
  if (!allowedTags.includes(tagName.toLowerCase())) {
    throw new Error(`Unsupported tag name: ${tagName}`);
  }
  
  // Create element
  const element = document.createElement(tagName);
  
  // Set text content safely
  if (content !== undefined && content !== null) {
    element.textContent = String(content);
  }
  
  // Apply validated attributes
  if (attributes && typeof attributes === 'object') {
    const blockedAttrs = ['onerror', 'onload', 'onclick', 'onmouseover', 'onkeypress', 'onchange'];
    
    Object.keys(attributes).forEach(attr => {
      const attrLower = attr.toLowerCase();
      
      // Skip event handlers and javascript: URLs
      if (blockedAttrs.includes(attrLower) || 
          (attrLower === 'href' && /^javascript:/i.test(attributes[attr])) ||
          (attrLower === 'src' && /^javascript:/i.test(attributes[attr]))) {
        console.warn(`Blocked potentially unsafe attribute: ${attr}`);
        return;
      }
      
      element.setAttribute(attr, attributes[attr]);
    });
  }
  
  return element;
}

// 6. Safe postMessage with origin validation
function setupSafePostMessageListener() {
  const trustedOrigins = [
    'https://trusted-site.com',
    'https://api.example.org'
  ];
  
  window.addEventListener('message', function(event) {
    // Origin validation
    if (!trustedOrigins.includes(event.origin)) {
      console.warn(`Message from untrusted origin rejected: ${event.origin}`);
      return;
    }
    
    // Validate structure
    try {
      const data = JSON.parse(event.data);
      
      // Validate expected message format
      if (!data.type || !data.action) {
        throw new Error('Invalid message format');
      }
      
      // Safe message handling (no eval or HTML injection)
      processVerifiedMessage(data);
    } catch (error) {
      console.error('Error processing message:', error);
    }
  });
}

// 7. Safe dynamic script loading with integrity
function loadScriptWithIntegrity(url, integrity, crossOrigin) {
  return new Promise((resolve, reject) => {
    // Validate URL (must be HTTPS)
    if (!/^https:\/\//i.test(url)) {
      return reject(new Error('Script URL must use HTTPS'));
    }
    
    const script = document.createElement('script');
    script.src = url;
    
    // Set integrity for subresource integrity protection
    if (integrity) {
      script.integrity = integrity;
    }
    
    if (crossOrigin) {
      script.crossOrigin = crossOrigin;
    }
    
    // Set event handlers
    script.onload = () => resolve(script);
    script.onerror = () => reject(new Error(`Failed to load script: ${url}`));
    
    // Append to document
    document.head.appendChild(script);
  });
}

// 8. Safe URL creation with encoding
function createSafeUrl(baseUrl, params) {
  // Validate base URL
  try {
    const url = new URL(baseUrl);
    
    // Ensure HTTPS
    if (url.protocol !== 'https:') {
      throw new Error('Only HTTPS URLs are allowed');
    }
    
    // Add parameters with proper encoding
    if (params && typeof params === 'object') {
      Object.keys(params).forEach(key => {
        url.searchParams.append(key, params[key]);
      });
    }
    
    return url.toString();
  } catch (error) {
    console.error('Invalid URL:', error);
    return null;
  }
}

// 9. Safe CSRF protection for forms
function addCSRFProtection(form) {
  // Check if form is valid element
  if (!(form instanceof HTMLFormElement)) {
    throw new TypeError('Expected HTMLFormElement');
  }
  
  // Get CSRF token from meta tag
  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
  
  if (!csrfToken) {
    console.error('CSRF token not found in page meta tags');
    return false;
  }
  
  // Add token to form
  const tokenInput = document.createElement('input');
  tokenInput.type = 'hidden';
  tokenInput.name = 'csrf_token';
  tokenInput.value = csrfToken;
  
  form.appendChild(tokenInput);
  
  // Ensure form has proper method
  if (!form.method || form.method.toLowerCase() === 'get') {
    form.method = 'post';
  }
  
  return true;
}

// 10. Safe storage usage with validation
function safeSaveToStorage(key, data) {
  // Type validation
  if (typeof key !== 'string') {
    throw new TypeError('Storage key must be a string');
  }
  
  // Prevent storing executable code
  if (typeof data === 'string' && /[<>]script|javascript:|eval|[<>]iframe|[<>]img|onerror=|onclick=|onload=/i.test(data)) {
    throw new Error('Potentially unsafe content detected');
  }
  
  // JSON stringify non-string data
  const safeValue = typeof data === 'string' ? data : JSON.stringify(data);
  
  // Encode and set with try/catch
  try {
    localStorage.setItem(key, safeValue);
    return true;
  } catch (error) {
    console.error('Storage error:', error);
    return false;
  }
}

// 11. Safe template rendering with escaping
function renderSafeTemplate(template, data) {
  // Helper function to escape HTML
  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }
  
  // Replace template variables with escaped values
  return template.replace(/\{\{\s*([^}]+)\s*\}\}/g, (match, key) => {
    const value = data[key.trim()];
    
    // Use empty string for undefined/null values
    if (value === undefined || value === null) {
      return '';
    }
    
    // Escape HTML in string values
    return typeof value === 'string' ? escapeHtml(value) : String(value);
  });
}

// 12. Safe createElement with strict validation
function createDomElement(tagName, options = {}) {
  // Whitelist allowed tags 
  const allowedTags = ['div', 'span', 'p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'ul', 'ol', 'li', 'a', 'button', 'input', 'label', 'select', 'option', 'textarea', 'img'];
  
  if (!allowedTags.includes(tagName.toLowerCase())) {
    throw new Error(`Tag not allowed: ${tagName}`);
  }
  
  const element = document.createElement(tagName);
  
  // Set content safely
  if (options.text) {
    element.textContent = options.text;
  }
  
  // Set attributes with validation
  if (options.attributes && typeof options.attributes === 'object') {
    const blockedAttributes = ['onload', 'onerror', 'onmouseover', 'onclick', 'onfocus'];
    const urlAttributes = ['href', 'src', 'action'];
    
    Object.entries(options.attributes).forEach(([attr, value]) => {
      // Skip blocked event handlers
      if (blockedAttributes.includes(attr.toLowerCase()) || attr.toLowerCase().startsWith('on')) {
        console.warn(`Blocked event handler attribute: ${attr}`);
        return;
      }
      
      // Validate URL attributes
      if (urlAttributes.includes(attr.toLowerCase())) {
        try {
          const url = new URL(value, window.location.origin);
          
          // Block javascript: URLs
          if (url.protocol === 'javascript:') {
            console.warn(`Blocked javascript: URL in ${attr}`);
            return;
          }
          
          element.setAttribute(attr, url.toString());
        } catch (e) {
          console.warn(`Invalid URL in attribute ${attr}`);
        }
      } else {
        element.setAttribute(attr, value);
      }
    });
  }
  
  // Add children if specified
  if (options.children && Array.isArray(options.children)) {
    options.children.forEach(child => {
      if (child instanceof HTMLElement) {
        element.appendChild(child);
      }
    });
  }
  
  return element;
}

// 13. Safe object property validation
function hasOwnSafeProperty(obj, prop) {
  // Prevent prototype chain access
  if (!obj || typeof obj !== 'object') {
    return false;
  }
  
  // Check using hasOwnProperty explicitly from Object prototype
  return Object.prototype.hasOwnProperty.call(obj, prop);
}

// 14. Safe fetch with validation and CSRF protection
async function safeFetchWithCSRF(url, options = {}) {
  // Validate URL
  try {
    new URL(url, window.location.origin);
  } catch (e) {
    throw new Error('Invalid URL');
  }
  
  // Default options
  const fetchOptions = {
    method: options.method || 'GET',
    headers: {
      'Content-Type': 'application/json',
      ...options.headers
    },
    credentials: 'same-origin'
  };
  
  // Add CSRF token for state-changing requests
  if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(fetchOptions.method.toUpperCase())) {
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
    
    if (csrfToken) {
      fetchOptions.headers['X-CSRF-Token'] = csrfToken;
    } else {
      console.warn('CSRF token not found, proceeding without it');
    }
  }
  
  // Add body if provided
  if (options.data) {
    fetchOptions.body = JSON.stringify(options.data);
  }
  
  // Execute fetch with error handling
  try {
    const response = await fetch(url, fetchOptions);
    
    if (!response.ok) {
      throw new Error(`HTTP error ${response.status}: ${response.statusText}`);
    }
    
    return await response.json();
  } catch (error) {
    console.error('Fetch error:', error);
    throw error;
  }
}

// 15. Safe use of Object.prototype methods
function safeObjectMethods(obj, propName) {
  // Use safe methods from Object.prototype
  const hasOwn = Object.prototype.hasOwnProperty.call(obj, propName);
  const toString = Object.prototype.toString.call(obj);
  const propertyIsEnumerable = Object.prototype.propertyIsEnumerable.call(obj, propName);
  
  // Use Object static methods for additional safety
  const descriptors = Object.getOwnPropertyDescriptors(obj);
  const keys = Object.keys(obj);
  
  return {
    hasOwn,
    toString,
    propertyIsEnumerable,
    keys,
    descriptor: descriptors[propName]
  };
}