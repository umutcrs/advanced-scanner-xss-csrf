// Parsers Test - XSS Vulnerabilities

// 1. Unsafe JSON.parse usage (Medium severity)
function processUserData() {
  // Get JSON data from query parameter or localStorage
  const userDataJson = getParameterByName('data') || localStorage.getItem('userData');
  
  try {
    // Vulnerable: directly parsing potentially malicious JSON without validation
    const userData = JSON.parse(userDataJson);
    
    // Using the parsed data in DOM
    if (userData && userData.name) {
      document.getElementById('username').textContent = userData.name;
    }
    
    if (userData && userData.settings && userData.settings.theme) {
      document.body.className = userData.settings.theme;
    }
    
    // Even more dangerous if the JSON contains HTML that will be inserted
    if (userData && userData.bio) {
      document.getElementById('user-bio').innerHTML = userData.bio;
    }
    
    return userData;
  } catch (e) {
    console.error('Error parsing JSON', e);
    return null;
  }
}

// 2. DOMParser unsafe usage (Medium severity)
function parseUserHtml() {
  // Get HTML from user input
  const userHtml = document.getElementById('html-input').value;
  
  // Vulnerable: parsing untrusted HTML and extracting elements
  const parser = new DOMParser();
  const doc = parser.parseFromString(userHtml, 'text/html');
  
  // This is dangerous if we extract and insert elements from parsed content
  const titles = doc.querySelectorAll('h1, h2, h3');
  const titleContainer = document.getElementById('extracted-titles');
  
  // Adding extracted elements to the document without sanitization
  titles.forEach(title => {
    // This can execute scripts if the title contains malicious content
    titleContainer.appendChild(title);
  });
  
  // Even more dangerous - extracting and using scripts
  const scripts = doc.querySelectorAll('script');
  scripts.forEach(script => {
    // Extremely dangerous - executing user-provided scripts
    const newScript = document.createElement('script');
    newScript.textContent = script.textContent;
    document.head.appendChild(newScript);
  });
}

// 3. HTML String Template Processing without Sanitization
function createTemplate() {
  const template = document.getElementById('template-input').value;
  const data = {
    username: getParameterByName('user'),
    role: getParameterByName('role'),
    content: getParameterByName('content')
  };
  
  // Vulnerable: Simple template processing without sanitization
  const processed = template.replace(/\\{\\{([^}]+)\\}\\}/g, (match, key) => {
    return data[key] || '';
  });
  
  // Inserting processed template with user data into the DOM
  document.getElementById('template-output').innerHTML = processed;
}

// Helper function
function getParameterByName(name) {
  const url = window.location.href;
  name = name.replace(/[\[\]]/g, '\\$&');
  const regex = new RegExp('[?&]' + name + '(=([^&#]*)|&|#|$)');
  const results = regex.exec(url);
  if (!results) return null;
  if (!results[2]) return '';
  return decodeURIComponent(results[2].replace(/\+/g, ' '));
}