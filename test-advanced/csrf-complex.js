// Advanced CSRF Test Cases
// This file contains complex CSRF vulnerabilities and mitigations

// 1. CSRF vulnerability with token but no SameSite cookie
function updateUserProfileCsrf(userId, userData) {
  const token = document.getElementById('csrf-token').value;
  
  fetch('/api/user/' + userId, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': token // Has token, but no SameSite cookie attributes
    },
    body: JSON.stringify(userData),
    credentials: 'include' // Includes cookies but without SameSite protection
  })
  .then(response => response.json())
  .then(data => console.log('Profile updated', data))
  .catch(error => console.error('Update failed', error));
}

// 2. Double-submit cookie pattern with implementation flaws
function setupDoubleSubmitTokens() {
  // Generate a random token
  const token = Math.random().toString(36).substring(2);
  
  // Set as cookie without Secure flag
  document.cookie = `csrf_token=${token}; path=/`; // Missing HttpOnly, SameSite and Secure flags
  
  // Also add to all forms
  document.querySelectorAll('form').forEach(form => {
    const input = document.createElement('input');
    input.type = 'hidden';
    input.name = 'csrf_token';
    input.value = token;
    form.appendChild(input);
  });
}

// 3. CSRF protection with insufficient token comparison
function validateCsrfToken(request) {
  const tokenFromCookie = getCookie('csrf_token');
  const tokenFromHeader = request.headers['x-csrf-token'];
  
  // Vulnerable: Compares only first 5 characters, making brute force easier
  return tokenFromCookie.substring(0, 5) === tokenFromHeader.substring(0, 5);
}

// 4. JSON-based CSRF vulnerability with content-type confusion
function submitDataJsonCsrf(data) {
  fetch('/api/process', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json' // Server may not check this properly
    },
    body: JSON.stringify(data),
    credentials: 'include'
  });
}

// 5. CSRF token with improper lifecycle management
function setupCsrfProtection() {
  let token = sessionStorage.getItem('csrf_token');
  
  // Create token if it doesn't exist
  if (!token) {
    token = generateRandomToken();
    sessionStorage.setItem('csrf_token', token);
  }
  
  // Token is not rotated after use, making it susceptible to replay attacks
  // Add token to Ajax requests
  attachTokenToRequests(token);
}

// 6. CSRF token with improper validation (timing attack)
function validateTokenUnsafe(token, expectedToken) {
  // Vulnerable to timing attacks
  if (token.length !== expectedToken.length) {
    return false;
  }
  
  // Character-by-character comparison creates timing side channel
  for (let i = 0; i < token.length; i++) {
    if (token[i] !== expectedToken[i]) {
      return false;
    }
  }
  
  return true;
}

// 7. CSRF with token in URL (leaking via Referer header)
function loadPageWithTokenInUrl() {
  const token = document.getElementById('csrf-token').value;
  
  // Putting CSRF token in URL is unsafe - can leak via Referer header
  window.location.href = `/dashboard?csrf_token=${token}`;
}

// 8. CSRF vulnerability in multi-step form
function initMultiStepForm() {
  // First step stores token but doesn't validate it 
  const firstStepForm = document.getElementById('step1-form');
  
  firstStepForm.addEventListener('submit', function(e) {
    e.preventDefault();
    
    // Store data in session storage
    const formData = new FormData(firstStepForm);
    sessionStorage.setItem('step1-data', JSON.stringify(Object.fromEntries(formData)));
    
    // Move to next step without validating CSRF token
    showFormStep(2);
  });
  
  // Final submission also lacks CSRF protection
  const finalStepForm = document.getElementById('step3-form');
  finalStepForm.addEventListener('submit', function(e) {
    e.preventDefault();
    
    // Combine all steps' data
    const step1Data = JSON.parse(sessionStorage.getItem('step1-data'));
    const step2Data = JSON.parse(sessionStorage.getItem('step2-data'));
    const formData = new FormData(finalStepForm);
    const step3Data = Object.fromEntries(formData);
    
    // Submit without CSRF token
    submitFormData({ ...step1Data, ...step2Data, ...step3Data });
  });
}

// 9. CSRF token storage in localStorage (vulnerable to XSS)
function setupInsecureCsrfStorage() {
  fetch('/api/csrf-token')
    .then(response => response.json())
    .then(data => {
      // Vulnerable: storing CSRF token in localStorage makes it accessible to XSS
      localStorage.setItem('csrf_token', data.token);
    });
}

// 10. CSRF vulnerability with token leakage via HTTP
function loadResourcesWithTokenLeakage() {
  const token = document.getElementById('csrf-token').value;
  
  // Load resources from third-party sites with token in URL
  const img = new Image();
  img.src = `http://third-party-cdn.example.com/image.jpg?token=${token}`;
  document.body.appendChild(img);
}

// 11. Cross-Origin Resource Sharing (CORS) misconfiguration enabling CSRF
function csrfWithCors() {
  // This function doesn't need to have vulnerable code itself
  // The vulnerability is in the server's CORS configuration
  // If the server has 'Access-Control-Allow-Origin: *' and 'Access-Control-Allow-Credentials: true'
  // then this request can be a CSRF vector
  fetch('https://api.vulnerable-site.com/update-account', {
    method: 'POST',
    credentials: 'include',
    body: JSON.stringify({ newEmail: 'attacker@example.com' })
  });
}

// 12. CSRF token generated from user input (predictable)
function generatePredictableCsrfToken(userId) {
  // Vulnerable: token is derived from user ID and timestamp
  const timestamp = Math.floor(Date.now() / 1000 / 3600); // Changes only hourly
  const token = btoa(userId + ':' + timestamp);
  
  document.cookie = `csrf_token=${token}; path=/`;
  return token;
}

// 13. Login CSRF (forced login to attacker's account)
function loginWithoutCsrfProtection(username, password) {
  fetch('/api/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`,
    credentials: 'include'
  });
}

// 14. CSRF via XML request (XML External Entity Attack combined with CSRF)
function sendXmlData(xmlData) {
  const xhr = new XMLHttpRequest();
  xhr.open('POST', '/api/process-xml', true);
  xhr.setRequestHeader('Content-Type', 'application/xml');
  xhr.withCredentials = true; // Sends cookies
  xhr.send(xmlData); // No CSRF protection, and potentially vulnerable to XXE as well
}

// 15. Clickjacking vulnerability that can lead to CSRF
function setupPageWithoutFrameProtection() {
  // This page doesn't set X-Frame-Options or CSP frame-ancestors
  // It contains sensitive buttons that can be clickjacked
  
  document.getElementById('delete-account').addEventListener('click', function() {
    if (confirm('Are you sure you want to delete your account?')) {
      fetch('/api/account', {
        method: 'DELETE',
        credentials: 'include'
      });
    }
  });
}

// Helper functions
function getCookie(name) {
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) return parts.pop().split(';').shift();
}

function generateRandomToken() {
  return Math.random().toString(36).substring(2);
}

function attachTokenToRequests(token) {
  // Set up axios or fetch interceptors to include token
}

function showFormStep(step) {
  // Show the specified form step
}

function submitFormData(data) {
  // Submit the combined form data
}