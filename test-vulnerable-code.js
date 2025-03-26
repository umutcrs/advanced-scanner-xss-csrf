// Example vulnerable code
function displayUserInput() {
  const userInput = document.getElementById('user-input').value;
  document.getElementById('output').innerHTML = userInput;
}

function createLink() {
  const url = document.getElementById('url-input').value;
  const element = document.createElement('a');
  element.setAttribute('href', url);
  element.innerHTML = 'Click me';
  document.body.appendChild(element);
}

function loadScript() {
  const scriptUrl = getParameterByName('src');
  const script = document.createElement('script');
  script.src = scriptUrl;
  document.head.appendChild(script);
}

// Potentially vulnerable eval usage
function calculateExpression() {
  const expr = document.getElementById('expression').value;
  const result = eval(expr);
  return result;
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