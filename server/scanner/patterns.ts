/**
 * Advanced XSS vulnerability patterns to check for in JavaScript code
 * Each pattern includes detailed descriptions, severity ratings, and secure code recommendations
 */
export const scanPatterns = [
  // Low severity - Document query selectors without direct vulnerability
  {
    type: "documentQuerySelector",
    regex: /document\.querySelector\(\s*(['"`][^'"`]*['"`])\s*\)/g,
    severity: "low" as const,
    title: "Document Query Selector Usage",
    description: "Using document.querySelector without proper validation can lead to targeting unintended elements. While not directly vulnerable, it can be part of a larger attack chain.",
    recommendation: "Ensure selectors are properly validated and consider using more specific selectors or data attributes for dynamic content.",
    recommendationCode: `// Bad practice
document.querySelector(userProvidedSelector);

// Better practice - validate selectors or use predefined selectors
// Using specific data attributes
document.querySelector(\`[data-user-id="\${sanitizeAttribute(userId)}"]\`);`
  },
  // Low severity - Text manipulation
  {
    type: "textManipulation",
    regex: /\.innerText\s*=\s*([^;]*)/g,
    severity: "low" as const,
    title: "Text Content Manipulation",
    description: "Using innerText with unsanitized data is generally safer than innerHTML but still may have unexpected results with certain inputs.",
    recommendation: "Ensure input is properly validated before using with innerText. For most cases, this is safe but consider textContent for better cross-browser compatibility.",
    recommendationCode: `// More consistent across browsers
element.textContent = validatedUserInput;

// When only need to display
const safeText = userInput.replace(/<\/?[^>]+(>|$)/g, "");
element.innerText = safeText;`
  },
  // Low severity - Potential unsafe URL construction
  {
    type: "urlConstruction",
    regex: /(?:['"`]https?:\/\/['"`]\s*\+|['"`]https?:\/\/[^'"`]*\$\{)/g,
    severity: "low" as const,
    title: "Unsafe URL Construction",
    description: "Constructing URLs by concatenating strings or using template literals can introduce URL injection vulnerabilities if not properly validated.",
    recommendation: "Use URL constructor or URLSearchParams to safely build URLs with user input.",
    recommendationCode: `// Instead of direct concatenation:
// const url = 'https://example.com/?q=' + userInput;

// Use URL and URLSearchParams:
const baseUrl = 'https://example.com/';
const url = new URL(baseUrl);
url.searchParams.append('q', userInput);

// Result: safe URL with properly encoded parameters
fetch(url.toString())
  .then(response => response.json())
  .then(data => console.log(data));`
  },
  // Low severity - Better form validation
  {
    type: "clientSideValidation",
    regex: /^\s*if\s*\([^\)]*(?:length|size|value)[\s\><=!]+[0-9]+/gm,
    severity: "low" as const,
    title: "Client-Side Only Validation",
    description: "Relying solely on client-side validation can be bypassed by attackers. While not directly an XSS issue, it can contribute to security risks.",
    recommendation: "Always implement server-side validation alongside client-side validation for a strong security posture.",
    recommendationCode: `// Client side validation (good for UX)
function validateClientSide(input) {
  if (!input || input.length > 100) {
    showError('Input too long or empty');
    return false;
  }
  return true;
}

// Server side validation (REQUIRED for security)
// In your server code:
function validateServerSide(input) {
  if (!input || typeof input !== 'string' || input.length > 100) {
    return { valid: false, error: 'Invalid input' };
  }
  // Additional checks as necessary
  return { valid: true };
}`
  },
  // Script source assignment - properly categorized and filtered
  {
    type: "scriptSrcAssignment",
    regex: /\b(?:script)(?:[A-Za-z0-9_]+)?\.src\s*=\s*(?!['"])/g,
    severity: "high" as const,
    title: "Dynamic Script Source Assignment",
    description: "Setting the src property of script elements with user input allows loading and executing untrusted code.",
    recommendation: "Always validate script sources against a whitelist of trusted domains.",
    recommendationCode: `function loadExternalScript(src) {
  // Whitelist of trusted domains
  const trustedDomains = [
    'cdn.trusted-site.com',
    'api.your-company.com',
    'cdn.jsdelivr.net'
  ];
  
  // Parse the URL to get the hostname
  let url;
  try {
    url = new URL(src, window.location.origin);
  } catch (e) {
    console.error("Invalid URL format");
    return;
  }
  
  // Check if the hostname is trusted
  if (!trustedDomains.includes(url.hostname)) {
    console.error("Untrusted script source domain");
    return;
  }
  
  // Now it's safer to load the script
  const script = document.createElement('script');
  script.src = src;
  document.head.appendChild(script);
}`
  },
  
  // Low severity - Image source assignment from user input (separate from script src)
  {
    type: "imageSrcAssignment",
    regex: /\b(?:img|image|picture|avatar|photo)(?:[A-Za-z0-9_]+)?\.src\s*=\s*(?!['"])/g,
    severity: "low" as const,
    title: "Dynamic Image Source Assignment",
    description: "Setting an image source dynamically is generally safe but may need validation to prevent information leakage or CSP bypass.",
    recommendation: "For dynamic image sources, use a valid URL format and apply proper sanitization if user inputs are involved.",
    recommendationCode: `// Ensure the path is safe before assigning to image src
function setImageSrc(imagePath, imgElement) {
  // Sanitize the path if it comes from user input
  // (Using textContent sanitization is one good approach)
  const tempNode = document.createTextNode(imagePath);
  const sanitizedPath = tempNode.textContent;
  
  // Validate the path format if needed
  if (!sanitizedPath.match(/^(https?:\\/\\/|\\/|\\.\\/)[\\w\\d\\-\\.\\/\\?\\=\\&\\%\\+\\#\\:]+$/i)) {
    console.error('Invalid image path format');
    return false;
  }
  
  imgElement.src = sanitizedPath;
  return true;
}`
  },
  // DOM-based XSS vulnerabilities - Critical risk
  {
    type: "innerHTML",
    regex: /\.innerHTML\s*=\s*([^;]*)/g,
    severity: "critical" as const,
    title: "innerHTML Injection",
    description: "Unfiltered user input is directly used with innerHTML, allowing attackers to inject and execute malicious scripts.",
    recommendation: "Always sanitize user input before inserting it into the DOM. Use textContent instead of innerHTML or implement a library like DOMPurify.",
    recommendationCode: `// Option 1: Use textContent (safest)
document.getElementById('output').textContent = userInput;

// Option 2: Use DOMPurify library
document.getElementById('output').innerHTML = DOMPurify.sanitize(userInput);`
  },
  {
    type: "outerHTML",
    regex: /\.outerHTML\s*=\s*([^;]*)/g,
    severity: "critical" as const,
    title: "outerHTML Injection",
    description: "Using outerHTML with unvalidated input can allow XSS attacks similar to innerHTML.",
    recommendation: "Avoid setting outerHTML directly with user input. Create new elements and set their text content instead.",
    recommendationCode: `// Instead of element.outerHTML = userInput, use:
const newElement = document.createElement('div');
newElement.textContent = userInput;
element.parentNode.replaceChild(newElement, element);`
  },
  {
    type: "insertAdjacentHTML",
    regex: /\.insertAdjacentHTML\s*\(\s*(['"`][^'"`]*['"`])\s*,\s*([^)]*)\)/g,
    severity: "high" as const,
    title: "insertAdjacentHTML Injection",
    description: "insertAdjacentHTML can execute script content if used with unvalidated input.",
    recommendation: "Sanitize user input before using insertAdjacentHTML or use safer alternatives like insertAdjacentText.",
    recommendationCode: `// Instead of element.insertAdjacentHTML('beforeend', userInput), use:
element.insertAdjacentText('beforeend', userInput);

// Or if HTML is needed, sanitize the input:
element.insertAdjacentHTML('beforeend', DOMPurify.sanitize(userInput));`
  },
  {
    type: "documentWrite",
    regex: /document\.write\s*\((?!\s*['"`]<!DOCTYPE)([^)]*)\)/g,
    severity: "high" as const,
    title: "Unsafe document.write() Usage",
    description: "Using document.write() with user input can lead to XSS vulnerabilities as it directly writes to the document.",
    recommendation: "Avoid document.write() and instead use safer DOM manipulation methods like createElement and appendChild.",
    recommendationCode: `// Instead of document.write(userInput), use:
const element = document.createElement('div');
element.textContent = userInput;
document.body.appendChild(element);`
  },
  {
    type: "documentWriteLn",
    regex: /document\.writeln\s*\((?!\s*['"`]<!DOCTYPE)([^)]*)\)/g,
    severity: "high" as const,
    title: "Unsafe document.writeln() Usage",
    description: "Similar to document.write(), document.writeln() can lead to XSS vulnerabilities when used with user input.",
    recommendation: "Avoid document.writeln() and use safer DOM manipulation methods.",
    recommendationCode: `// Instead of document.writeln(userInput), use:
const element = document.createElement('div');
element.textContent = userInput + '\\n';
document.body.appendChild(element);`
  },
  {
    type: "dangerouslySetInnerHTML",
    regex: /dangerouslySetInnerHTML\s*:\s*\{\s*__html\s*:\s*([^}]*)\}/g,
    severity: "critical" as const,
    title: "React dangerouslySetInnerHTML Misuse",
    description: "Using dangerouslySetInnerHTML in React with unvalidated input can lead to XSS vulnerabilities.",
    recommendation: "Sanitize HTML input before using dangerouslySetInnerHTML, or preferably avoid using it.",
    recommendationCode: `// Instead of:
<div dangerouslySetInnerHTML={{ __html: userProvidedHTML }} />

// Sanitize the input first:
import DOMPurify from 'dompurify';

<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userProvidedHTML) }} />

// Or better yet, avoid innerHTML and use React's component model:
function UserContent({ content }) {
  return <div>{content}</div>;
}`
  },

  // Code evaluation vulnerabilities - Critical risk
  {
    type: "eval",
    regex: /eval\s*\(([^)]*)\)/g,
    severity: "critical" as const,
    title: "Unsafe eval() Usage",
    description: "The use of eval() with user input creates a severe XSS vulnerability that allows arbitrary code execution.",
    recommendation: "Avoid using eval() with user input. For mathematical expressions, use safer alternatives like math.js library or Function constructor with proper input validation.",
    recommendationCode: `// Option 1: Use a math library
function calculateExpression() {
  const expr = document.getElementById('expression').value;
  try {
    // Validate that the input contains only mathematical expressions
    if (!/^[0-9\\+\\-\\*\\/\\(\\)\\.\\s]*$/.test(expr)) {
      throw new Error("Invalid expression");
    }
    const result = math.evaluate(expr); // Using math.js
    return result;
  } catch(e) {
    return "Error: Invalid expression";
  }
}`
  },
  {
    type: "functionConstructor",
    regex: /new\s+Function\s*\(([^)]*)\)/g,
    severity: "critical" as const,
    title: "Function Constructor Misuse",
    description: "The Function constructor is similar to eval() and can execute arbitrary code if given user input.",
    recommendation: "Avoid using the Function constructor with user input. Use safer alternatives for dynamic code execution.",
    recommendationCode: `// Instead of:
const fn = new Function('param', userCode);

// Consider a more restrictive approach:
// 1. Use a template literals with fixed code
const fn = (param) => {
  // Fixed operations here
  return param * 2;
};

// 2. Or if you need configurability, use a whitelist approach
const allowedOperations = {
  'double': (x) => x * 2,
  'square': (x) => x * x,
  'increment': (x) => x + 1
};

// Then use the selected operation safely
const operation = allowedOperations[userSelection] || ((x) => x);
const result = operation(value);`
  },
  {
    type: "setTimeout",
    regex: /setTimeout\s*\(\s*(['"`][^'"`]*['"`])/g,
    severity: "high" as const,
    title: "Unsafe setTimeout String Evaluation",
    description: "Using setTimeout with a string argument acts like eval() and can execute injected code.",
    recommendation: "Always use function references with setTimeout instead of strings.",
    recommendationCode: `// Instead of:
setTimeout("doSomething(" + userInput + ")", 1000);

// Use a function reference:
setTimeout(() => {
  doSomething(userInput);
}, 1000);`
  },
  {
    type: "setInterval",
    regex: /setInterval\s*\(\s*(['"`][^'"`]*['"`])/g,
    severity: "high" as const,
    title: "Unsafe setInterval String Evaluation",
    description: "Using setInterval with a string argument acts like eval() and can execute injected code.",
    recommendation: "Always use function references with setInterval instead of strings.",
    recommendationCode: `// Instead of:
setInterval("updateData(" + userInput + ")", 5000);

// Use a function reference:
setInterval(() => {
  updateData(userInput);
}, 5000);`
  },
  {
    type: "indirectEval",
    regex: /\(\s*eval\s*\)\s*\(/g,
    severity: "critical" as const,
    title: "Indirect eval() Usage",
    description: "Using eval indirectly (e.g., (eval)()) can bypass some CSP restrictions and still execute arbitrary code.",
    recommendation: "Never use eval in any form. Refactor code to avoid dynamic code execution.",
    recommendationCode: `// Instead of indirect eval:
// (eval)('alert(document.cookie)');

// Use a more explicit and secure approach:
function processCommand(command, allowedCommands) {
  if (allowedCommands.includes(command)) {
    // Execute pre-defined functions associated with commands
    return commandHandlers[command]();
  }
  return null;
}`
  },
  {
    type: "jsGlobalWithEval",
    regex: /(?:window|self|top|global)\s*\[\s*(['"`]eval['"`]|['"`]Function['"`])\s*\]/g,
    severity: "critical" as const,
    title: "Dynamic Access to eval/Function",
    description: "Accessing eval or Function constructor dynamically through bracket notation can be used to bypass security scanners.",
    recommendation: "Avoid accessing eval or Function constructor in any way, including through bracket notation.",
    recommendationCode: `// Don't do this:
// const evil = window['eval'];
// evil('alert(document.cookie)');

// Instead, use a safer approach to handle dynamic operations:
function executeOperation(opName, ...args) {
  const safeOperations = {
    'add': (a, b) => a + b,
    'multiply': (a, b) => a * b,
    // other safe operations
  };
  
  if (safeOperations.hasOwnProperty(opName)) {
    return safeOperations[opName](...args);
  }
  throw new Error('Operation not allowed');
}`
  },

  // URL-based vulnerabilities
  {
    type: "setAttribute",
    regex: /\.setAttribute\s*\(\s*(['"])(?:href|src|action|formaction|data|href|xlink:href|poster|background|ping)\1\s*,\s*([^)]*)\)/g,
    severity: "high" as const,
    title: "Unsafe setAttribute Usage on Sensitive Attributes",
    description: "Unvalidated user input in URL attributes could allow javascript: protocol exploits and other URL-based attacks.",
    recommendation: "Validate URLs and ensure they don't begin with javascript: or data: protocols before using them in attributes.",
    recommendationCode: `function createLink() {
  const url = document.getElementById('url-input').value;
  
  // Validate URL
  if (!url.match(/^(https?:\\/\\/|\\/|\\.\\/|\\.\\.\\/)[\\w\\d\\-\\.\\/\\?\\=\\&\\%\\+\\#\\:]*/i)) {
    console.error("Invalid URL detected");
    return;
  }
  
  // Explicitly check against dangerous protocols
  if (/^javascript:|^data:|^vbscript:|^file:/i.test(url)) {
    console.error("Potentially malicious URL protocol detected");
    return;
  }
  
  const element = document.createElement('a');
  element.setAttribute('href', url);
  element.textContent = 'Click me'; // Use textContent, not innerHTML
  document.body.appendChild(element);
}`
  },
  {
    type: "setAttributeEvent",
    regex: /\.setAttribute\s*\(\s*(['"])(?:on\w+)\1\s*,\s*([^)]*)\)/g,
    severity: "critical" as const,
    title: "Event Handler Injection via setAttribute",
    description: "Setting event handlers (onclick, onload, etc.) via setAttribute with unvalidated input allows direct code execution.",
    recommendation: "Never set event handlers using setAttribute. Use addEventListener instead and pass function references, not strings.",
    recommendationCode: `// Instead of:
element.setAttribute('onclick', userInput);

// Use addEventListener with a function:
element.addEventListener('click', (event) => {
  // Safe handling of user action
  console.log('Element clicked');
  // Use userInput in a safe context
  displayMessage(sanitizeInput(userInput));
});

// For dynamic functions, use a whitelist approach:
const allowedActions = {
  'showAlert': () => { alert('Safe alert'); },
  'toggleVisibility': () => { element.classList.toggle('hidden'); }
};

// Then use it safely:
const actionName = userInput;
if (allowedActions.hasOwnProperty(actionName)) {
  element.addEventListener('click', allowedActions[actionName]);
}`
  },
  {
    type: "locationAssignment",
    regex: /(?:location|window\.location|document\.location)\s*=\s*([^;]*)/g,
    severity: "medium" as const,
    title: "Unsafe Location Assignment",
    description: "Setting location directly from user input can lead to javascript: URL exploits.",
    recommendation: "Validate URLs before setting location to prevent javascript: protocol injections.",
    recommendationCode: `function redirect(url) {
  // Validate URL format
  if (!url.match(/^(https?:\\/\\/|\\/|\\.\\/|\\.\\.\\/)[\\w\\d\\-\\.\\/\\?\\=\\&\\%\\+\\#\\:]*/i)) {
    console.error("Invalid URL format");
    return;
  }
  
  // Explicitly check against dangerous protocols
  if (/^javascript:|^data:|^vbscript:|^file:/i.test(url)) {
    console.error("Potentially malicious URL protocol detected");
    return;
  }
  
  // Now it's safe to redirect
  location.href = url;
}`
  },
  {
    type: "locationHref",
    regex: /(?:location\.href|location\.replace|location\.assign)\s*\(\s*([^)]*)\)/g,
    severity: "medium" as const,
    title: "Unsafe Location Method Usage",
    description: "Using location.href, location.replace, or location.assign with user input can lead to javascript: URL exploits.",
    recommendation: "Validate URLs before using location methods to navigate.",
    recommendationCode: `function navigateTo(url) {
  // Validate the URL
  if (!/^(https?:\/\/|\/|\.\/|\.\.\/)/i.test(url)) {
    console.error("Invalid URL format");
    return;
  }
  
  if (/^javascript:|^data:|^vbscript:|^file:/i.test(url)) {
    console.error("Potentially malicious URL protocol detected");
    return;
  }
  
  // Now we can safely navigate
  location.href = url;
}`
  },
  {
    type: "locationPropertyAssignment",
    regex: /(?:location\.search|location\.hash|location\.pathname|location\.host|location\.hostname)\s*=\s*([^;]*)/g,
    severity: "medium" as const,
    title: "Unsafe Location Property Assignment",
    description: "Setting location properties from user input can lead to javascript: URL exploits and other injection attacks.",
    recommendation: "Validate and sanitize input before setting location properties.",
    recommendationCode: `function updateLocationHash(hashValue) {
  // Remove any script or dangerous content
  const sanitizedHash = hashValue.replace(/[<>(){}\\[\\]'"\`]/g, '');
  
  // Ensure it starts with #
  const safeHash = sanitizedHash.startsWith('#') ? sanitizedHash : '#' + sanitizedHash;
  
  // Now it's safer to set
  location.hash = safeHash;
}`
  },
  {
    type: "aHref",
    regex: /\.href\s*=\s*([^;]*)/g,
    severity: "medium" as const,
    title: "Direct href Property Assignment",
    description: "Setting the href property directly with user input can lead to javascript: protocol exploits.",
    recommendation: "Validate URLs before assigning to href properties.",
    recommendationCode: `function setLinkHref(element, url) {
  // Validate URL format and protocol
  if (!url.match(/^(https?:\\/\\/|\\/|\\.\\/|\\.\\.\\/)[\\w\\d\\-\\.\\/\\?\\=\\&\\%\\+\\#\\:]*/i) || 
      /^javascript:|^data:|^vbscript:|^file:/i.test(url)) {
    console.error("Invalid or potentially malicious URL");
    return;
  }
  
  element.href = url;
}`
  },
  {
    type: "scriptSrc",
    regex: /\.src\s*=\s*([^;]*)(?=\s*;|\s*$)/g,
    severity: "high" as const,
    title: "Dynamic Script Source Assignment",
    description: "Setting the src property of script elements with user input allows loading and executing untrusted code.",
    recommendation: "Always validate script sources against a whitelist of trusted domains.",
    recommendationCode: `function loadExternalScript(src) {
  // Whitelist of trusted domains
  const trustedDomains = [
    'cdn.trusted-site.com',
    'api.your-company.com',
    'cdn.jsdelivr.net'
  ];
  
  // Parse the URL to get the hostname
  let url;
  try {
    url = new URL(src, window.location.origin);
  } catch (e) {
    console.error("Invalid URL format");
    return;
  }
  
  // Check if the hostname is trusted
  if (!trustedDomains.includes(url.hostname)) {
    console.error("Untrusted script source domain");
    return;
  }
  
  // Now it's safer to load the script
  const script = document.createElement('script');
  script.src = src;
  document.head.appendChild(script);
}`
  },
  {
    type: "objectData",
    regex: /\.data\s*=\s*([^;]*)(?=\s*;|\s*$)/g,
    severity: "medium" as const,
    title: "Unsafe Object Data Property Assignment",
    description: "Setting the data property of <object> elements can lead to loading malicious content or scripts.",
    recommendation: "Validate the data URL and only allow trusted sources and safe file types.",
    recommendationCode: `function setObjectData(objectElement, dataUrl) {
  // Whitelist of allowed file extensions
  const allowedExtensions = ['.pdf', '.svg', '.png', '.jpg', '.jpeg', '.gif'];
  
  // Check if URL has an allowed extension
  const hasAllowedExtension = allowedExtensions.some(ext => 
    dataUrl.toLowerCase().endsWith(ext));
  
  if (!hasAllowedExtension) {
    console.error("Object data URL has disallowed file extension");
    return;
  }
  
  // Validate URL format
  if (!/^(https?:\/\/|\/|\.\/|\.\.\/)/i.test(dataUrl) || 
      /^javascript:|^data:|^vbscript:|^file:/i.test(dataUrl)) {
    console.error("Invalid or potentially malicious data URL");
    return;
  }
  
  objectElement.data = dataUrl;
}`
  },
  {
    type: "iframeSrc",
    regex: /(?:\.src\s*=\s*|\ssrc\s*=\s*['"])[^'"]*(?:['"])?(?=.*<\s*iframe)/g,
    severity: "high" as const,
    title: "Unsafe iframe Source",
    description: "Setting iframe src with unvalidated input can lead to loading malicious content or same-origin policy bypass.",
    recommendation: "Validate iframe sources and consider using the sandbox attribute.",
    recommendationCode: `function setIframeSrc(iframe, src) {
  // Whitelist of trusted domains for iframes
  const trustedDomains = [
    'trusted-site.com',
    'safe-embed.com'
  ];
  
  // Validate URL
  try {
    const url = new URL(src, window.location.origin);
    
    // Check if hostname is in trusted domains
    const isTrusted = trustedDomains.some(domain => 
      url.hostname === domain || url.hostname.endsWith('.' + domain));
      
    if (!isTrusted) {
      console.error("Untrusted iframe source domain");
      return;
    }
    
    // Apply sandbox attribute for additional security
    iframe.sandbox = 'allow-scripts allow-same-origin';
    iframe.src = src;
    
  } catch (e) {
    console.error("Invalid URL format");
    return;
  }
}`
  },

  // Dynamic HTML Generation
  {
    type: "templateLiteralHtml",
    regex: /\$\{(?:[^{}]*)\}(?=[^]*?(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write|document\.writeln))/g,
    severity: "high" as const,
    title: "Template Literal in HTML Context",
    description: "Using template literals with user input to generate HTML can lead to XSS vulnerabilities.",
    recommendation: "Sanitize user inputs before including them in template literals used for HTML.",
    recommendationCode: `// Instead of:
element.innerHTML = \`<div>User: \${userName}</div>\`;

// Sanitize the input:
const sanitizedName = DOMPurify.sanitize(userName);
element.innerHTML = \`<div>User: \${sanitizedName}</div>\`;

// Or better yet, avoid innerHTML:
element.textContent = '';
const div = document.createElement('div');
div.textContent = \`User: \${userName}\`;
element.appendChild(div);`
  },
  {
    type: "htmlFromConcatenation",
    regex: /['"`](?:[^'"`]*?)<[^>]*>(?:[^'"`]*?)['"`](?:[^;]*?)(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write)/g,
    severity: "high" as const,
    title: "HTML String Concatenation",
    description: "Building HTML strings through concatenation with user input can lead to XSS vulnerabilities.",
    recommendation: "Use DOM APIs to create elements instead of building HTML strings, or sanitize input with DOMPurify.",
    recommendationCode: `// Instead of:
const html = '<div class="user">' + userData.name + '</div>';
element.innerHTML = html;

// Use DOM APIs:
const div = document.createElement('div');
div.className = 'user';
div.textContent = userData.name;
element.appendChild(div);`
  },
  {
    type: "unsafeJQueryHtml",
    regex: /\$\([^)]*\)\.(?:html|append|prepend|after|before|replaceWith)\s*\(\s*([^)]*)\)/g,
    severity: "high" as const,
    title: "Unsafe jQuery HTML Manipulation",
    description: "Using jQuery's HTML manipulation methods with unvalidated input can lead to XSS vulnerabilities.",
    recommendation: "Sanitize input before using jQuery HTML methods or use text() instead of html().",
    recommendationCode: `// Instead of:
$('#element').html(userInput);

// Use text() for plain text:
$('#element').text(userInput);

// Or sanitize first:
$('#element').html(DOMPurify.sanitize(userInput));

// For more complex DOM manipulation, create elements safely:
const $div = $('<div>').addClass('user-content');
$div.text(userInput);
$('#container').append($div);`
  },
  {
    type: "documentCreateElement",
    regex: /document\.createElement\s*\(\s*(?:(?:variable\s*=\s*)|(?:[a-zA-Z_$][a-zA-Z0-9_$]*\s*=\s*))?([^)]*)\)/g,
    severity: "medium" as const,
    title: "Dynamic Element Creation",
    description: "Creating HTML elements with dynamic tag names from user input can lead to unexpected elements or XSS.",
    recommendation: "Never use user input to determine element tag names.",
    recommendationCode: `// Instead of:
// const tagName = userInput; // DANGEROUS
// const element = document.createElement(tagName);

// Use a whitelist approach:
function createSafeElement(tagName) {
  const allowedTags = ['div', 'span', 'p', 'h1', 'h2', 'h3', 'ul', 'ol', 'li'];
  
  if (!allowedTags.includes(tagName.toLowerCase())) {
    console.error('Attempted to create disallowed element type:', tagName);
    return document.createElement('span'); // fallback to safe element
  }
  
  return document.createElement(tagName);
}`
  },

  // Advanced injection techniques
  {
    type: "scriptElement",
    regex: /document\.createElement\s*\(\s*['"]script['"]\s*\)/g,
    severity: "medium" as const,
    title: "Dynamic Script Creation",
    description: "Dynamically creating script elements and setting their content or src attribute can execute malicious code.",
    recommendation: "Never load scripts from untrusted sources. Use a whitelist approach to validate script URLs before loading.",
    recommendationCode: `function loadScript(src) {
  // Whitelist of allowed script sources
  const allowedSources = [
    'https://trusted-cdn.com/',
    'https://your-own-domain.com/scripts/'
  ];
  
  // Check if URL is from allowed source
  const isAllowed = allowedSources.some(source => 
    src.startsWith(source));
    
  if (!isAllowed) {
    console.error("Blocked loading script from untrusted source");
    return;
  }
  
  const script = document.createElement('script');
  script.src = src;
  document.head.appendChild(script);
}`
  },
  {
    type: "scriptTextContent",
    regex: /\.(?:textContent|innerText|text)\s*=\s*([^;]*)(?=\s*;?\s*document\.(?:body|head)\.appendChild\s*\(\s*script\s*\))/g,
    severity: "critical" as const,
    title: "Dynamic Script Content Injection",
    description: "Setting the content of a script element with user input before appending it to the document allows arbitrary code execution.",
    recommendation: "Never set script content from user input. Use a predefined set of scripts or functions.",
    recommendationCode: `// NEVER do this:
// const script = document.createElement('script');
// script.textContent = userInput;
// document.head.appendChild(script);

// Instead, use a safer approach:
function executeAllowedOperation(operationName, ...args) {
  const operations = {
    'showUserProfile': (userId) => fetchAndDisplayUserProfile(userId),
    'loadDashboard': () => navigateToDashboard(),
    // other predefined operations
  };
  
  if (operations.hasOwnProperty(operationName)) {
    operations[operationName](...args);
  } else {
    console.error('Operation not allowed');
  }
}`
  },
  {
    type: "postMessageOrigin",
    regex: /addEventListener\s*\(\s*['"]message['"]\s*,\s*(?:function\s*\([^)]*\)\s*\{(?:[^{}]|(?:\{[^{}]*\}))*\}|[^,)]+)(?!\s*,[^,]+\.origin)/g,
    severity: "medium" as const,
    title: "postMessage Without Origin Check",
    description: "Handling postMessage events without verifying the origin can lead to XSS attacks from malicious websites.",
    recommendation: "Always validate the origin of received messages.",
    recommendationCode: `// Instead of:
window.addEventListener('message', function(event) {
  // Process event.data without checking origin
  processMessage(event.data);
});

// Add origin validation:
window.addEventListener('message', function(event) {
  // Check that the origin is from a trusted domain
  const trustedOrigins = ['https://trusted-site.com', 'https://partner-site.org'];
  
  if (trustedOrigins.includes(event.origin)) {
    // Safe to process the message
    processMessage(event.data);
  } else {
    console.warn('Received message from untrusted origin:', event.origin);
  }
});`
  },
  {
    type: "jsonParse",
    regex: /JSON\.parse\s*\(([^)]*)\)/g,
    severity: "medium" as const,
    title: "Potential JSON Injection",
    description: "Using JSON.parse on unsanitized input can lead to prototype pollution or other injection attacks.",
    recommendation: "Validate JSON input before parsing and consider using a safer JSON parsing library.",
    recommendationCode: `// Before using JSON.parse:
function safeJSONParse(data) {
  // Check if data is a string
  if (typeof data !== 'string') {
    throw new Error('Invalid input: expected string');
  }
  
  // Optional: Check for suspicious patterns
  if (/\\__proto__|constructor|prototype/.test(data)) {
    throw new Error('Potentially malicious input detected');
  }
  
  try {
    return JSON.parse(data);
  } catch (e) {
    console.error('JSON parsing error:', e);
    throw new Error('Invalid JSON format');
  }
}`
  },
  {
    type: "domParser",
    regex: /(?:new\s+DOMParser\(\)\.parseFromString|createContextualFragment)\s*\(([^,)]*)/g,
    severity: "medium" as const,
    title: "Unsafe HTML Parsing",
    description: "Parsing HTML with DOMParser or createContextualFragment without sanitization can lead to XSS when the parsed content is inserted into the DOM.",
    recommendation: "Sanitize HTML before parsing it with DOMParser or createContextualFragment.",
    recommendationCode: `// Instead of:
const parser = new DOMParser();
const doc = parser.parseFromString(userInput, 'text/html');
container.appendChild(doc.body.firstChild);

// Sanitize first:
const parser = new DOMParser();
const sanitizedInput = DOMPurify.sanitize(userInput);
const doc = parser.parseFromString(sanitizedInput, 'text/html');
container.appendChild(doc.body.firstChild);`
  },
  {
    type: "parseFromString",
    regex: /\.parseFromString\s*\(\s*([^,)]*)/g,
    severity: "medium" as const,
    title: "Unsafe parseFromString Usage",
    description: "Using parseFromString with unvalidated input can lead to XSS vulnerabilities when the parsed content is added to the DOM.",
    recommendation: "Sanitize input before parsing as XML or HTML.",
    recommendationCode: `// Instead of:
const parser = new DOMParser();
const xmlDoc = parser.parseFromString(userInput, 'text/xml');

// Sanitize first for HTML content:
const safeInput = DOMPurify.sanitize(userInput);
const safeDoc = parser.parseFromString(safeInput, 'text/html');

// For XML, validate strictly:
function parseXmlSafely(xmlString) {
  try {
    // Check for potentially malicious XML features
    if (xmlString.includes('<!ENTITY') || 
        xmlString.includes('<!DOCTYPE')) {
      throw new Error('XML with potentially malicious features detected');
    }
    
    const parser = new DOMParser();
    return parser.parseFromString(xmlString, 'text/xml');
  } catch (error) {
    console.error('XML parsing error:', error);
    return null;
  }
}`
  },
  {
    type: "innerText",
    regex: /\.innerText\s*=\s*(?:.*?[+\`].*?)/g,
    severity: "low" as const,
    title: "Potential innerText Misuse",
    description: "While safer than innerHTML, setting innerText with concatenated strings or template literals could lead to less obvious XSS issues in certain contexts.",
    recommendation: "Use textContent instead of innerText for better security, and avoid complex string concatenation with user input.",
    recommendationCode: `// Instead of:
element.innerText = 'Hello, ' + userName + '!';

// Prefer textContent:
element.textContent = 'Hello, ' + userName + '!';

// Or for more complex content, use DOM methods:
element.textContent = '';
const greeting = document.createTextNode('Hello, ');
const name = document.createTextNode(userName);
const exclamation = document.createTextNode('!');
element.appendChild(greeting);
element.appendChild(name);
element.appendChild(exclamation);`
  },
  
  // Framework-specific vulnerabilities
  {
    type: "angularBypassSecurityTrustHtml",
    regex: /(?:bypassSecurityTrustHtml|bypassSecurityTrustScript|bypassSecurityTrustStyle|bypassSecurityTrustUrl|bypassSecurityTrustResourceUrl)\s*\(\s*([^)]*)\)/g,
    severity: "critical" as const,
    title: "Angular Security Bypass",
    description: "Using Angular's bypassSecurity methods with user input disables Angular's built-in sanitization, creating XSS vulnerabilities.",
    recommendation: "Never bypass Angular's security with untrusted input. Use Angular's sanitization methods instead.",
    recommendationCode: `// Instead of:
// this.sanitizedHtml = this.sanitizer.bypassSecurityTrustHtml(userInput);

// Use Angular's DomSanitizer properly:
import { DomSanitizer } from '@angular/platform-browser';

// In your component:
constructor(private sanitizer: DomSanitizer) {}

// Then sanitize the input:
this.sanitizedHtml = this.sanitizer.sanitize(SecurityContext.HTML, userInput);

// Only bypass security for completely static, developer-controlled content:
this.trustedStaticHtml = this.sanitizer.bypassSecurityTrustHtml('<b>Static HTML here</b>');`
  },
  {
    type: "vueVBind",
    regex: /v-html\s*=\s*["']([^"']*)["']/g,
    severity: "high" as const,
    title: "Unsafe Vue v-html Usage",
    description: "Vue.js v-html directive renders content as HTML without sanitization, allowing XSS if user input is used.",
    recommendation: "Avoid v-html with user input. Use v-text or mustache syntax ({{ }}) for displaying text.",
    recommendationCode: `<!-- Instead of: -->
<!-- <div v-html="userMessage"></div> -->

<!-- Use v-text or mustache syntax: -->
<div v-text="userMessage"></div>
<!-- or -->
<div>{{ userMessage }}</div>

<!-- If you must use HTML, sanitize first: -->
<!-- In your component: -->
<script>
import DOMPurify from 'dompurify';

export default {
  data() {
    return {
      userMessage: '<p>User input</p>'
    }
  },
  computed: {
    sanitizedMessage() {
      return DOMPurify.sanitize(this.userMessage);
    }
  }
}
</script>

<!-- Then in your template: -->
<div v-html="sanitizedMessage"></div>`
  },
  
  // DOM clobbering vulnerabilities
  {
    type: "documentGetElementById",
    regex: /document\.getElementById\s*\(\s*(['"`][^'"`]*['"`])\s*\)/g,
    severity: "low" as const,
    title: "Potential DOM Clobbering Vulnerability",
    description: "Using getElementById with a fixed string can be exploited through DOM clobbering if the ID is also used as an object property.",
    recommendation: "Ensure IDs used with getElementById are not also used as object property names in your code.",
    recommendationCode: `// Vulnerable pattern:
// const config = {};
// config.endpoint = document.getElementById('endpoint').value;
// fetch(config.endpoint + '/data');

// Safer approach:
function getElementValueById(id) {
  const element = document.getElementById(id);
  // Validate element is of expected type
  if (element && element instanceof HTMLInputElement) {
    return element.value;
  }
  return null;
}

// Then use with validation:
const endpoint = getElementValueById('endpoint');
if (endpoint && isValidUrl(endpoint)) {
  fetch(endpoint + '/data');
}`
  },
  
  // Advanced XSS through DOM manipulation
  {
    type: "documentCreateRange",
    regex: /createContextualFragment\s*\(\s*([^)]*)\)/g,
    severity: "high" as const,
    title: "Unsafe Range.createContextualFragment Usage",
    description: "Using createContextualFragment with user input can lead to XSS when the fragments are inserted into the DOM.",
    recommendation: "Sanitize HTML before using createContextualFragment.",
    recommendationCode: `// Instead of:
const range = document.createRange();
const fragment = range.createContextualFragment(userInput);
document.body.appendChild(fragment);

// Sanitize first:
const sanitizedHtml = DOMPurify.sanitize(userInput);
const range = document.createRange();
const fragment = range.createContextualFragment(sanitizedHtml);
document.body.appendChild(fragment);`
  },
  
  // Advanced event-based XSS
  {
    type: "eventHandlerProperty",
    regex: /\.(?:onclick|onmouseover|onload|onerror|onsubmit|onfocus|onblur|onkeyup|onkeydown|onchange|onunload)\s*=\s*([^;]*)/g,
    severity: "high" as const,
    title: "Event Handler Property Assignment",
    description: "Setting event handler properties (onclick, onload, etc.) with user input allows direct code execution.",
    recommendation: "Never set event handler properties using user input. Use addEventListener with function references.",
    recommendationCode: `// Instead of:
element.onclick = 'alert("' + userInput + '")';
// or
element.onclick = function() { processUserInput(userInput); };

// Use addEventListener with a function:
element.addEventListener('click', function(event) {
  // Safely handle the input
  displayMessage(sanitizeInput(userInput));
});`
  },
  
  // Meta-programming vulnerabilities
  {
    type: "objectDefineProperty",
    regex: /Object\.defineProperty\s*\(\s*([^,]*),\s*([^,]*),\s*{/g,
    severity: "medium" as const,
    title: "Potential Prototype Pollution via defineProperty",
    description: "Using Object.defineProperty with user-controlled property names can lead to prototype pollution or object property clobbering.",
    recommendation: "Validate object and property names before using defineProperty, especially with user input.",
    recommendationCode: `// Instead of:
// Object.defineProperty(target, userInput, { value: 'some value' });

// Validate the property name first:
function safeDefineProperty(obj, propName, descriptor) {
  // Disallow prototype chain or constructor manipulation
  if (propName === '__proto__' || 
      propName === 'constructor' || 
      propName === 'prototype') {
    console.error('Attempted to define unsafe property:', propName);
    return false;
  }
  
  // Only allow whitelisted properties if using user input
  const allowedProps = ['name', 'description', 'value', 'isActive'];
  if (!allowedProps.includes(propName)) {
    console.error('Property name not in allowed list:', propName);
    return false;
  }
  
  Object.defineProperty(obj, propName, descriptor);
  return true;
}`
  },
  
  // HTML5-specific vulnerabilities
  {
    type: "srcdocAssignment",
    regex: /\.srcdoc\s*=\s*([^;]*)/g,
    severity: "critical" as const,
    title: "iframe srcdoc Injection",
    description: "Setting the srcdoc attribute of an iframe with user input allows direct HTML/JavaScript execution in the iframe context.",
    recommendation: "Sanitize HTML content before setting iframe.srcdoc.",
    recommendationCode: `// Instead of:
iframe.srcdoc = userProvidedHTML;

// Sanitize first:
iframe.srcdoc = DOMPurify.sanitize(userProvidedHTML, {
  SANITIZE_DOM: true,
  FORBID_TAGS: ['script', 'iframe', 'object', 'embed'],
  FORBID_ATTR: ['onerror', 'onload', 'onclick']
});

// Or better yet, use a safer alternative:
iframe.srcdoc = '<html><body>' + 
                '<div>' + escapeHtml(userMessage) + '</div>' +
                '</body></html>';

// Helper function to escape HTML
function escapeHtml(html) {
  const div = document.createElement('div');
  div.textContent = html;
  return div.innerHTML;
}`
  },
  
  // URL manipulation vulnerabilities
  {
    type: "urlSearchParamsAppend",
    regex: /\.append\s*\(\s*([^,]*),\s*([^)]*)\)(?=\s*(?:\.toString\(\)|new URLSearchParams))/g,
    severity: "low" as const,
    title: "Unsafe URLSearchParams Manipulation",
    description: "Appending unvalidated user input to URLSearchParams could lead to XSS when the resulting URL is used in a dangerous context.",
    recommendation: "Validate and sanitize parameters before adding them to URLSearchParams.",
    recommendationCode: `// Instead of:
const params = new URLSearchParams();
params.append('q', userInput);
someElement.src = 'https://example.com/search?' + params.toString();

// Validate and sanitize first:
function addSafeParam(params, name, value) {
  // Remove potentially dangerous characters
  const sanitized = String(value).replace(/[<>(){}\\[\\]'"\`]/g, '');
  params.append(name, sanitized);
}

const params = new URLSearchParams();
addSafeParam(params, 'q', userInput);
someElement.src = 'https://example.com/search?' + params.toString();`
  },
  
  // Advanced DOM-based XSS vulnerabilities with CSP bypass
  {
    type: "trustedTypesEscape",
    regex: /TrustedHTML\.unsafelyCreate\s*\(\s*([^)]*)\)/g,
    severity: "critical" as const,
    title: "Trusted Types Policy Bypass",
    description: "Using TrustedHTML.unsafelyCreate bypasses the entire Trusted Types protection, allowing direct script execution even with CSP in place.",
    recommendation: "Never use the unsafelyCreate method in production. Use proper sanitization and create specific Trusted Types policies.",
    recommendationCode: `// Instead of using unsafelyCreate method:
// const html = TrustedHTML.unsafelyCreate(userInput);

// Define a proper Trusted Types policy:
const myPolicy = trustedTypes.createPolicy('my-sanitizer', {
  createHTML: (input) => {
    const sanitized = DOMPurify.sanitize(input);
    return sanitized;
  }
});

// Then use the policy to create trusted HTML:
const trustedHtml = myPolicy.createHTML(userInput);
element.innerHTML = trustedHtml; // Safe with proper policy`
  },
  {
    type: "domClobbering",
    regex: /\.namedItem\s*\(\s*([^)]*)\)|\.getElementById\s*\(\s*['"]([^'"]*)['"]\s*\)\s*\|\|\s*.+/g,
    severity: "medium" as const,
    title: "Potential DOM Clobbering Vulnerability",
    description: "DOM Clobbering is a type of attack that uses HTML to override properties/elements that scripts expect, potentially enabling XSS despite CSP.",
    recommendation: "Always check the type of the returned object from DOM lookups and never use the || operator to provide fallbacks for DOM lookups.",
    recommendationCode: `// Instead of:
const config = document.getElementById('config') || { settings: defaultSettings };

// Do type checking:
const configElement = document.getElementById('config');
const config = configElement instanceof HTMLElement ? 
  JSON.parse(configElement.textContent || '{}') : 
  { settings: defaultSettings };

// Or for namedItem:
const item = document.getElementsByName('user')[0];
if (item && item instanceof HTMLInputElement) {
  // Now it's safe to use
  console.log(item.value);
}`
  },
  {
    type: "baseHref",
    regex: /document\.getElementsByTagName\s*\(\s*['"]base['"]\s*\)\s*\[\s*0\s*\]\.href\s*=\s*([^;]*)/g,
    severity: "high" as const,
    title: "Dynamic Base Tag Modification",
    description: "Modifying the base tag href attribute can redirect relative URLs to an attacker-controlled domain, enabling complex XSS attacks.",
    recommendation: "Never dynamically modify the base tag. If necessary, validate the URL against a strict whitelist.",
    recommendationCode: `// Don't modify base href dynamically:
// document.getElementsByTagName('base')[0].href = userInput;

// If necessary, use a whitelist approach:
function setBaseUrl(url) {
  const allowedDomains = ['example.com', 'api.myapp.com', 'cdn.myapp.com'];
  
  try {
    const parsed = new URL(url);
    if (allowedDomains.includes(parsed.hostname)) {
      // Use the original base element or create if it doesn't exist
      let baseElement = document.getElementsByTagName('base')[0];
      if (!baseElement) {
        baseElement = document.createElement('base');
        document.head.appendChild(baseElement);
      }
      baseElement.href = url;
    } else {
      console.error('Domain not in whitelist');
    }
  } catch (e) {
    console.error('Invalid URL');
  }
}`
  },
  {
    type: "jsonpCallback",
    regex: /[?&](callback|jsonp)=([^&]+)/g,
    severity: "high" as const,
    title: "JSONP Callback Parameter Injection",
    description: "When implementing JSONP endpoints, callback parameter validation is critical to prevent XSS attacks through the dynamically generated script.",
    recommendation: "Always validate JSONP callback parameter against a strict regex pattern allowing only alphanumeric characters and some basic symbols.",
    recommendationCode: `// Server-side JSONP callback validation (Node.js example)
function validateJsonpCallback(callback) {
  const validPattern = /^[a-zA-Z0-9_$.]+$/;
  return validPattern.test(callback) ? callback : 'defaultCallback';
}

app.get('/api/jsonp', (req, res) => {
  const data = { message: 'Hello world' };
  const callback = validateJsonpCallback(req.query.callback);
  
  res.setHeader('Content-Type', 'application/javascript');
  res.send(\`\${callback}(\${JSON.stringify(data)})\`);
});`
  },
  {
    type: "cssExpressionInjection",
    regex: /\.style\.cssText\s*=\s*([^;]*)|element\.style\s*=\s*(['"]expression\s*\([^)]*\))/g,
    severity: "medium" as const,
    title: "CSS Expression/Style Injection",
    description: "Setting cssText or style directly with unsanitized input allows XSS via CSS expressions in older IE browsers and may leak data via advanced CSS selectors.",
    recommendation: "Sanitize CSS before setting style properties or use individual property assignment instead of bulk style setting.",
    recommendationCode: `// Instead of:
element.style.cssText = userInput;

// Set individual properties after validation:
function setElementStyles(element, stylesObj) {
  const allowedProps = ['color', 'backgroundColor', 'fontSize', 'margin', 'padding'];
  
  Object.keys(stylesObj).forEach(prop => {
    if (allowedProps.includes(prop)) {
      // Validate values based on property type
      const value = stylesObj[prop];
      
      // Example validation for color
      if (prop === 'color' || prop === 'backgroundColor') {
        // Allow only valid color formats
        if (/^(#[0-9a-f]{3,6}|rgb\(\s*\d+\s*,\s*\d+\s*,\s*\d+\s*\)|rgba\(\s*\d+\s*,\s*\d+\s*,\s*\d+\s*,\s*[0-1](\.\d+)?\s*\)|[a-z-]+)$/i.test(value)) {
          element.style[prop] = value;
        }
      } else {
        // Basic sanitization for other properties
        element.style[prop] = value.replace(/expression|javascript|behavior|calc|url/gi, '');
      }
    }
  });
}`
  },
  {
    type: "htmlTemplateInjection",
    regex: /document\.createElement\s*\(\s*['"]template['"]\s*\)[\s\S]{0,50}\.innerHTML\s*=\s*([^;]*)/g,
    severity: "high" as const,
    title: "HTML Template Element Injection",
    description: "Setting innerHTML on a template element can lead to XSS when the template content is later cloned and added to the document.",
    recommendation: "Sanitize any HTML before inserting it into a template element, even though templates aren't directly rendered.",
    recommendationCode: `// Instead of:
const template = document.createElement('template');
template.innerHTML = userInput;

// Sanitize the input:
const template = document.createElement('template');
template.innerHTML = DOMPurify.sanitize(userInput, {
  RETURN_DOM_FRAGMENT: false,
  RETURN_DOM: false
});

// Then use it safely:
const clone = document.importNode(template.content, true);
document.body.appendChild(clone);`
  },
  {
    type: "dynamicScriptInjection",
    regex: /document\.write\s*\(\s*['"]<script[^>]*>['"]\s*\+\s*([^+]*)\s*\+\s*['"]<\/script>['"]\s*\)/g,
    severity: "critical" as const,
    title: "Dynamic Script Tag Injection",
    description: "Creating script tags with unvalidated content allows direct code execution regardless of the context.",
    recommendation: "Never use document.write to inject scripts. Use safer alternatives like fetch for AJAX operations.",
    recommendationCode: `// Instead of:
document.write('<script>' + userInput + '</script>');

// Fetch data from API:
fetch('/api/data')
  .then(response => response.json())
  .then(data => {
    // Handle the data safely
    processData(data);
  })
  .catch(error => {
    console.error('Error fetching data:', error);
  });

// If you need to load external scripts, use a whitelist:
function loadScript(url) {
  const trustedDomains = ['cdn.example.com', 'api.example.org'];
  try {
    const parsedUrl = new URL(url);
    if (trustedDomains.includes(parsedUrl.hostname)) {
      const script = document.createElement('script');
      script.src = url;
      document.head.appendChild(script);
    }
  } catch (e) {
    console.error('Invalid URL');
  }
}`
  },
  {
    type: "angularTemplateInjection",
    regex: /\{\{(.+?)(?:\| trustAs(?:Html|Js|ResourceUrl))*\}\}/g,
    severity: "critical" as const,
    title: "Angular Template Injection",
    description: "Angular expressions within {{ }} can lead to XSS if unsanitized input is used, especially when bypassing Angular's built-in sanitization with pipes like trustAsHtml.",
    recommendation: "Never use the Angular trustAs* pipes with user input. Use Angular's [innerHTML] with DomSanitizer when needed.",
    recommendationCode: `// In Angular component:
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

export class MyComponent {
  userContent: string;
  safeContent: SafeHtml;
  
  constructor(private sanitizer: DomSanitizer) {}
  
  // Use this approach when you must render HTML
  processUserContent(content: string): void {
    // Sanitize the HTML
    this.userContent = content;
    
    // Angular will sanitize this automatically when using [innerHTML]
    // Only bypass for known safe content
    if (this.isFromTrustedSource(content)) {
      this.safeContent = this.sanitizer.bypassSecurityTrustHtml(content);
    }
  }
  
  private isFromTrustedSource(content: string): boolean {
    // Implement validation logic here
    return false; // Default to safe approach
  }
}

// In template:
// <div [innerHTML]="safeContent"></div>`
  },
  {
    type: "prototypeExpando",
    regex: /Object\.prototype\.__(?:defineGetter|defineSetter|lookupGetter|lookupSetter|proto)__\s*=\s*([^;]*)/g,
    severity: "critical" as const,
    title: "Prototype Pollution via Special Properties",
    description: "Modifying Object.prototype with special properties like __proto__ can enable advanced prototype pollution attacks leading to XSS.",
    recommendation: "Never modify Object.prototype directly. Use Object.create(null) for maps to avoid prototype inheritance issues.",
    recommendationCode: `// Instead of objects with inherited prototype:
const userDataMap = {}; // Vulnerable to prototype pollution

// Use Object.create(null) to create objects without prototype:
const safeMap = Object.create(null);

// When handling JSON:
function safeParseJson(jsonString) {
  try {
    // Parse the JSON
    const parsed = JSON.parse(jsonString);
    
    // Recursively freeze objects to prevent modifications
    function deepFreeze(obj) {
      if (obj && typeof obj === 'object' && !Object.isFrozen(obj)) {
        Object.freeze(obj);
        Object.getOwnPropertyNames(obj).forEach(prop => deepFreeze(obj[prop]));
      }
      return obj;
    }
    
    return deepFreeze(parsed);
  } catch (e) {
    console.error('Invalid JSON', e);
    return null;
  }
}`
  },
  {
    type: "jqueryHtmlMethod",
    regex: /\$\(.*\)\.html\(\s*([^)]*)\)/g,
    severity: "high" as const,
    title: "jQuery .html() Method Misuse",
    description: "Using jQuery's .html() method with unfiltered user input allows XSS attacks similar to innerHTML.",
    recommendation: "Use .text() instead of .html() or sanitize content before using .html().",
    recommendationCode: `// Instead of:
$('#element').html(userInput);

// Use text() for displaying user content:
$('#element').text(userInput);

// Or sanitize if HTML is required:
$('#element').html(DOMPurify.sanitize(userInput));

// For templating, prefer a safe approach:
const template = $('#template').html();
const rendered = template
  .replace('{{safeContent}}', escapeHtml(userInput.content))
  .replace('{{safeTitle}}', escapeHtml(userInput.title));
$('#element').html(rendered);

function escapeHtml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}`
  },
  {
    type: "vulnerableJsonParse",
    regex: /JSON\.parse\s*\(\s*([^)]*)\)/g,
    severity: "medium" as const,
    title: "Unsafe JSON Parsing",
    description: "Parsing JSON from untrusted sources can lead to prototype pollution or DoS attacks with carefully crafted payloads.",
    recommendation: "Always validate JSON structure and use a JSON schema validator before parsing sensitive data.",
    recommendationCode: `// Import a JSON schema validator like Ajv
import Ajv from 'ajv';

// Define a schema for expected JSON structure
const userSchema = {
  type: 'object',
  properties: {
    id: { type: 'number' },
    name: { type: 'string', maxLength: 100 },
    email: { type: 'string', format: 'email' },
    preferences: {
      type: 'object',
      properties: {
        theme: { type: 'string', enum: ['light', 'dark', 'system'] },
        notifications: { type: 'boolean' }
      },
      additionalProperties: false
    }
  },
  required: ['id', 'name', 'email'],
  additionalProperties: false
};

// Safely parse and validate JSON
function safeJsonParse(jsonString) {
  try {
    // First parse the JSON
    const data = JSON.parse(jsonString);
    
    // Then validate against schema
    const ajv = new Ajv();
    const validate = ajv.compile(userSchema);
    
    if (validate(data)) {
      return data;
    } else {
      console.error('Invalid data structure:', validate.errors);
      return null;
    }
  } catch (e) {
    console.error('JSON parsing error:', e);
    return null;
  }
}`
  }
];
