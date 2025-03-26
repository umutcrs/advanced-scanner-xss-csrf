// SAFE - Include CSRF token with credentials:
function safeAuthenticatedRequest(url, method, data) {
  // Get CSRF token from meta tag or cookie
  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || 
                   getCookie('XSRF-TOKEN');
  
  if (!csrfToken) {
    console.error('Missing CSRF token - cannot make secure request');
    return Promise.reject(new Error('Missing CSRF token'));
  }
  
  return fetch(url, {
    method: method,
    credentials: 'include',  // Send cookies
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': csrfToken  // Add CSRF token header
    },
    body: JSON.stringify(data)
  });
}

// Helper function to get cookie by name
function getCookie(name) {
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) return parts.pop().split(';').shift();
  return null;
}

// Example usage
function updateUserProfile() {
  const userData = {
    name: 'John Doe',
    email: 'john@example.com'
  };
  
  safeAuthenticatedRequest('/api/profile', 'POST', userData)
    .then(response => response.json())
    .then(data => console.log('Profile updated:', data))
    .catch(error => console.error('Error updating profile:', error));
}