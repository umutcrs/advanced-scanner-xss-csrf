/**
 * Advanced XSS vulnerability patterns to check for in JavaScript code
 * Each pattern includes detailed descriptions, severity ratings, and secure code recommendations
 */
export const scanPatterns = [
  // Direct meta tag content assignment with user input - extra pattern
  {
    type: "directMetaTagContentAssignment",
    regex: /meta(?:Tag)?\.content\s*=\s*(?!['"])[^;]+(?:user|url|param|get|location|search|hash)/gi,
    severity: "medium" as const,
    title: "Direct Meta Tag Content Assignment",
    description: "Setting meta tag content directly with user-controllable data can lead to metadata manipulation, SEO poisoning, or in some cases to redirection attacks.",
    recommendation: "Sanitize and validate user input before assigning to meta tag content attribute.",
    recommendationCode: `// UNSAFE pattern:
// metaTag.content = userDescription; // Direct assignment from user input

// SAFER approach:
function setSafeMetaDescription(description) {
  // 1. Validate input type
  if (typeof description !== 'string') {
    console.error('Invalid meta description type');
    return false;
  }
  
  // 2. Length validation
  if (description.length > 160) { // Standard meta description max length
    description = description.substring(0, 160);
  }
  
  // 3. Remove potential HTML or script content
  description = description
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
  
  // 4. Set the sanitized content
  const metaTag = document.createElement('meta');
  metaTag.name = "description";
  metaTag.content = description;
  document.head.appendChild(metaTag);
  
  return true;
}

// Usage:
const userDescription = getUrlParameter('description');
setSafeMetaDescription(userDescription);`
  },
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
  },
  
  // modern DOM-based XSS vulnerabilities
  {
    type: "shadowDomInnerHTML",
    regex: /shadowRoot\.innerHTML\s*=\s*([^;]*)/g,
    severity: "critical" as const,
    title: "Shadow DOM innerHTML Injection",
    description: "Setting innerHTML on shadowRoot can lead to XSS vulnerabilities, even though Shadow DOM provides some level of isolation.",
    recommendation: "Avoid using innerHTML with Shadow DOM. Use standard DOM manipulation methods or lit-html templates instead.",
    recommendationCode: `// Instead of shadowRoot.innerHTML = userInput
const shadowRoot = element.attachShadow({mode: 'open'});

// Use append with text nodes
const text = document.createTextNode(userInput);
shadowRoot.append(text);

// Or for more complex content use lit-html or other template libraries
import {html, render} from 'lit-html';
const template = html\`<div>\${userInput}</div>\`;
render(template, shadowRoot);`
  },
  {
    type: "customElementInnerHTML",
    regex: /customElements\.define\s*\([^{]*\{[^}]*innerHTML\s*=[^}]*\}/g,
    severity: "high" as const,
    title: "Custom Element innerHTML Manipulation",
    description: "Using innerHTML within Custom Elements can lead to XSS vulnerabilities if user input is not properly sanitized.",
    recommendation: "Use textContent instead of innerHTML or properly sanitize the input before using innerHTML in custom elements.",
    recommendationCode: `// In a custom element class
class SafeElement extends HTMLElement {
  constructor() {
    super();
    
    // Use a shadow root for encapsulation
    const shadow = this.attachShadow({mode: 'open'});
    
    // Create a safe span element
    const content = document.createElement('span');
    
    // Use textContent instead of innerHTML
    content.textContent = this.getAttribute('data-content') || '';
    
    // Append to shadow DOM
    shadow.appendChild(content);
  }
}

customElements.define('safe-element', SafeElement);`
  },
  {
    type: "domPurifyBypass",
    regex: /DOMPurify\.sanitize\s*\([^)]*\{[^}]*RETURN_DOM\s*:\s*true[^}]*\}/g,
    severity: "medium" as const,
    title: "Potential DOMPurify Configuration Risk",
    description: "Using DOMPurify with RETURN_DOM option can potentially lead to DOM Clobbering attacks if not properly configured.",
    recommendation: "When using DOMPurify with RETURN_DOM, also set SANITIZE_DOM: true and ensure you're using the latest version of DOMPurify.",
    recommendationCode: `// Safer DOMPurify configuration
const clean = DOMPurify.sanitize(userInput, {
  RETURN_DOM: true,
  SANITIZE_DOM: true, // Prevents DOM clobbering
  FORBID_TAGS: ['script', 'style', 'iframe', 'frame', 'object', 'embed'],
  FORBID_ATTR: ['srcset', 'action', 'formaction', 'xlink:href']
});

// Or better yet, if you don't need a DOM:
const cleanHTML = DOMPurify.sanitize(userInput);
element.innerHTML = cleanHTML;`
  },
  // Framework-specific XSS attacks
  {
    type: "reactDangerSetHTML",
    regex: /<div[^>]*dangerouslySetInnerHTML\s*=\s*\{\s*\{[^}]*__html\s*:/g,
    severity: "critical" as const,
    title: "React dangerouslySetInnerHTML Direct Usage",
    description: "Direct JSX usage of dangerouslySetInnerHTML creates risk of XSS attacks if the input is not properly sanitized.",
    recommendation: "Always sanitize content with a library like DOMPurify before using dangerouslySetInnerHTML.",
    recommendationCode: `import DOMPurify from 'dompurify';

function SafeHTML({ content }) {
  const sanitizedContent = DOMPurify.sanitize(content);
  
  return <div dangerouslySetInnerHTML={{ __html: sanitizedContent }} />;
}`
  },
  {
    type: "angularTemplateInjection",
    regex: /\[\[innerHTML\]\]\s*=\s*"[^"]*"/g,
    severity: "critical" as const,
    title: "Angular Template Injection",
    description: "Using [innerHTML] in Angular templates can lead to XSS vulnerabilities with unsanitized input.",
    recommendation: "Use Angular's built-in DomSanitizer to mark trusted HTML, and prefer to use property binding with textContent instead.",
    recommendationCode: `// In component TypeScript file
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

export class MyComponent {
  rawHtml: string = '<some html from user>';
  safeHtml: SafeHtml;
  
  constructor(private sanitizer: DomSanitizer) {
    // Only use bypassSecurityTrustHtml when you absolutely need HTML
    // and have properly validated/sanitized the input
    this.safeHtml = this.sanitizer.bypassSecurityTrustHtml(this.rawHtml);
  }
}

// In template
<div [innerHTML]="safeHtml"></div>

// Best approach - don't use innerHTML at all if possible
<div>{{ textContent }}</div>`
  },
  {
    type: "vueTemplateInjection",
    regex: /v-html\s*=\s*(?:"|')?[^"'<>]*(?:"|')?/g,
    severity: "high" as const,
    title: "Vue v-html Directive Misuse",
    description: "Using v-html directive in Vue templates with unsanitized user input can lead to XSS vulnerabilities.",
    recommendation: "Avoid v-html with user-generated content. Use v-text or mustache syntax instead, or sanitize HTML with DOMPurify before binding.",
    recommendationCode: `// Instead of:
<div v-html="userProvidedContent"></div>

// Use v-text or mustache syntax:
<div v-text="userProvidedContent"></div>
<div>{{ userProvidedContent }}</div>

// If HTML is necessary, sanitize first:
<script>
import DOMPurify from 'dompurify';

export default {
  data() {
    return {
      rawContent: '<user content>'
    }
  },
  computed: {
    safeContent() {
      return DOMPurify.sanitize(this.rawContent);
    }
  }
}
</script>

<template>
  <div v-html="safeContent"></div>
</template>`
  },
  // Advanced JavaScript context XSS
  {
    type: "postMessageXSS",
    regex: /window\.addEventListener\s*\(\s*["']message["']\s*,\s*(?:function\s*\([^)]*\)|[^,]*)\s*\{[^}]*innerHTML/g,
    severity: "high" as const,
    title: "Insecure postMessage Handler",
    description: "Using innerHTML with data received from postMessage without proper origin checking and content validation can lead to XSS.",
    recommendation: "Always validate origin and sanitize data from postMessage before using it in the DOM.",
    recommendationCode: `// Secure postMessage handler
window.addEventListener('message', function(event) {
  // Always validate origin
  if (event.origin !== 'https://trusted-site.com') {
    console.error('Received message from untrusted origin:', event.origin);
    return;
  }
  
  try {
    // Validate the data structure
    const data = typeof event.data === 'string' ? JSON.parse(event.data) : event.data;
    
    if (!data || typeof data !== 'object') {
      throw new Error('Invalid message format');
    }
    
    // Process the data safely
    if (data.type === 'update-content') {
      // Use textContent instead of innerHTML
      document.getElementById('message').textContent = data.content;
    }
  } catch (error) {
    console.error('Error processing message:', error);
  }
});`
  },
  {
    type: "jsonpVulnerability",
    regex: /document\.createElement\s*\(\s*["']script["']\s*\)[^;]*\.src\s*=\s*(?!["']https?:\/\/[^"']+\.js["'])/g,
    severity: "high" as const,
    title: "Insecure JSONP Implementation",
    description: "Dynamic script creation for JSONP without proper URL validation can lead to XSS vulnerabilities.",
    recommendation: "Validate the JSONP URL and specify callback parameter name explicitly. Prefer using fetch with CORS instead of JSONP when possible.",
    recommendationCode: `// Safer JSONP implementation
function loadJSONP(url, callback) {
  // Validate URL
  if (!url.startsWith('https://trusted-api.com/') || url.includes('javascript:')) {
    console.error('Invalid or untrusted JSONP URL');
    return;
  }
  
  // Create a unique callback name
  const callbackName = 'jsonp_callback_' + Math.round(100000 * Math.random());
  
  // Create script element
  const script = document.createElement('script');
  
  // Clean up after execution
  window[callbackName] = function(data) {
    delete window[callbackName];
    document.body.removeChild(script);
    callback(data);
  };
  
  // Add callback parameter to URL
  const separator = url.includes('?') ? '&' : '?';
  script.src = \`\${url}\${separator}callback=\${callbackName}\`;
  
  // Append to document
  document.body.appendChild(script);
}

// Even better - use fetch with CORS instead when possible:
async function fetchData(url) {
  try {
    const response = await fetch('https://trusted-api.com/data', {
      method: 'GET',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' }
    });
    
    if (!response.ok) {
      throw new Error('Network response was not ok');
    }
    
    const data = await response.json();
    return data;
  } catch (error) {
    console.error('Error fetching data:', error);
  }
}`
  },
  // DOM Clobbering based XSS
  {
    type: "domClobbering",
    regex: /getElementById\s*\(\s*['"](?:body|head|forms|anchors)['"].*?\)/g,
    severity: "medium" as const,
    title: "Potential DOM Clobbering Vulnerability",
    description: "Using getElementById with certain reserved names can be exploited through DOM Clobbering attacks to bypass security measures.",
    recommendation: "Avoid using common DOM property names as element IDs and validate element types after selection.",
    recommendationCode: `// Instead of directly trusting getElementById for sensitive operations
const element = document.getElementById('forms');

// Add type checking
if (element && element instanceof HTMLElement && !(element instanceof HTMLFormElement)) {
  // Now we know it's a regular element, not a clobbered DOM property
  // Safe to proceed
  element.textContent = 'Content updated safely';
}

// Better yet, use more specific selectors or add a prefix to your IDs
// to avoid collision with DOM properties
const safeElement = document.getElementById('app-forms');
`
  },
  // Local storage based XSS
  {
    type: "localStorageXSS",
    regex: /localStorage\.getItem\s*\([^)]*\)[^;]*(?:innerHTML|outerHTML|document\.write)/g,
    severity: "high" as const,
    title: "Unsafe localStorage Data Usage",
    description: "Using localStorage data without sanitization in HTML contexts can lead to stored XSS vulnerabilities.",
    recommendation: "Always sanitize data retrieved from localStorage before inserting it into the DOM.",
    recommendationCode: `// Instead of:
const userData = localStorage.getItem('userData');
document.getElementById('profile').innerHTML = userData;

// Sanitize the data first:
const userData = localStorage.getItem('userData');
if (userData) {
  // Option 1: Use textContent for plain text
  document.getElementById('profile').textContent = userData;
  
  // Option 2: If HTML is needed, sanitize properly
  import DOMPurify from 'dompurify';
  document.getElementById('profile').innerHTML = DOMPurify.sanitize(userData);
}`
  },
  // Client-side template injection
  {
    type: "templateInjection",
    regex: /new\s+(?:Function|Function\s*\()\s*\(\s*(['"`])[^'"]*\$\{[^'"]*\1\s*\)/g,
    severity: "critical" as const,
    title: "Client-side Template Injection",
    description: "Creating functions with template literals that incorporate user input can lead to code execution vulnerabilities.",
    recommendation: "Never use template literals with Function constructor. Use safe templating libraries instead.",
    recommendationCode: `// Instead of dangerous template execution:
// const template = \`<div>\${userInput}</div>\`;
// const renderTemplate = new Function('return \`' + template + '\`')();

// Use a safe templating approach:
import { sanitize } from 'dompurify';

// Option 1: Simple replacement with sanitization
function safeTemplate(template, data) {
  // First sanitize all data values
  const sanitizedData = {};
  for (const key in data) {
    if (Object.prototype.hasOwnProperty.call(data, key)) {
      sanitizedData[key] = typeof data[key] === 'string' 
        ? sanitize(data[key])
        : data[key];
    }
  }
  
  // Then do simple replacements
  return template.replace(/\\{\\{([^}]+)\\}\\}/g, (match, key) => {
    return sanitizedData[key.trim()] || '';
  });
}

// Usage:
const template = '<div>{{userName}}</div>';
const result = safeTemplate(template, { userName: userInput });
element.innerHTML = result;

// Option 2: Use established template libraries like Handlebars
// that have security built in`
  },
  // Modern browser API XSS vectors
  {
    type: "trustedTypesViolation",
    regex: /Element\.prototype\.innerHTML\s*=\s*([^;]*)/g,
    severity: "high" as const,
    title: "Potential Trusted Types Bypass",
    description: "Overriding Element.prototype.innerHTML can bypass Trusted Types policy protections in modern browsers.",
    recommendation: "Never override built-in DOM property setters. Use proper Trusted Types policies instead.",
    recommendationCode: `// Instead of dangerous prototype manipulation:
// Element.prototype.innerHTML = function(value) { /* custom implementation */ };

// Use proper Trusted Types:
if (window.trustedTypes && window.trustedTypes.createPolicy) {
  // Create a policy
  const sanitizePolicy = window.trustedTypes.createPolicy('sanitize-html', {
    createHTML: (string) => DOMPurify.sanitize(string)
  });
  
  // Use the policy
  const element = document.getElementById('content');
  element.innerHTML = sanitizePolicy.createHTML(userInput);
} else {
  // Fallback for browsers without Trusted Types support
  const element = document.getElementById('content');
  element.innerHTML = DOMPurify.sanitize(userInput);
}`
  },
  // DOM-XSS through SVG
  {
    type: "svgScriptInsertion",
    regex: /(?:document\.createElementNS\s*\([\'"](http:\/\/www\.w3\.org\/2000\/svg)[\'"],\s*[\'"]script[\'"]\)|<svg[^>]*><script[^>]*>)/g,
    severity: "critical" as const,
    title: "SVG Script Insertion",
    description: "SVG can contain embedded scripts which will execute when injected into the DOM, creating XSS vulnerabilities.",
    recommendation: "Sanitize SVG content before inserting it into the DOM or use SVG viewers that strip script content.",
    recommendationCode: `// Option 1: Clean SVG before inserting
import DOMPurify from 'dompurify';

// Configure DOMPurify to handle SVG
DOMPurify.addHook('afterSanitizeAttributes', function(node) {
  // Remove potentially dangerous attributes or event handlers
  if (node.tagName === 'SVG' || node.namespaceURI === 'http://www.w3.org/2000/svg') {
    if (node.hasAttribute('onload') || node.hasAttribute('onerror')) {
      node.removeAttribute('onload');
      node.removeAttribute('onerror');
    }
  }
});

// Then clean the SVG
const cleanSvg = DOMPurify.sanitize(svgInput, {
  USE_PROFILES: { svg: true, svgFilters: true }
});
container.innerHTML = cleanSvg;

// Option 2: Create a dedicated SVG viewer that restricts execution
function safeSvgViewer(svgString, container) {
  // Create a sandboxed iframe
  const frame = document.createElement('iframe');
  frame.sandbox = 'allow-same-origin';
  frame.style.border = 'none';
  frame.style.width = '100%';
  frame.style.height = '100%';
  container.appendChild(frame);
  
  // Write the SVG to the iframe without scripts
  const cleanSvg = DOMPurify.sanitize(svgString, {
    USE_PROFILES: { svg: true },
    FORBID_TAGS: ['script']
  });
  
  frame.contentDocument.open();
  frame.contentDocument.write(cleanSvg);
  frame.contentDocument.close();
}`
  },
  // URL schemes in JavaScript
  {
    type: "javaScriptUrlScheme",
    regex: /(?:location|window\.location|document\.location|window\.open|location\.href|location\.replace)\s*(?:=|\()[\'"]\s*javascript:/ig,
    severity: "critical" as const,
    title: "JavaScript URL Scheme Used",
    description: "Using the javascript: URL scheme allows direct code execution and is a common XSS vector.",
    recommendation: "Never use javascript: URLs, especially with user input. Validate all URLs to ensure they use safe schemes like https:.",
    recommendationCode: `// Instead of javascript: URLs for actions
// NEVER do this:
// link.href = "javascript:executeFunction('" + userInput + "')";
// window.location = "javascript:alert('message')";

// Use event handlers and validate URLs:
function isValidUrl(url) {
  // Check for safe URL schema
  return /^(https?:\/\/|\/|\.\/|\.\.\/)/i.test(url) && 
         !/^javascript:/i.test(url) && 
         !/^data:/i.test(url);
}

// For links:
const button = document.getElementById('action-button');
button.addEventListener('click', (e) => {
  e.preventDefault();
  // Execute your function directly
  executeFunction(safeUserInput);
});

// For redirects:
function safeRedirect(url) {
  if (isValidUrl(url)) {
    window.location = url;
  } else {
    console.error('Invalid URL detected:', url);
  }
}`
  },
  // CSS-based expressions (legacy but important to detect)
  {
    type: "cssExpressionXSS",
    regex: /style\s*=\s*['"]\s*.*?expression\s*\(|\.style\.cssText\s*=\s*['"].*?expression\s*\(/ig,
    severity: "medium" as const,
    title: "CSS Expression Usage",
    description: "CSS expressions in older IE browsers can execute JavaScript code, creating a vector for XSS attacks.",
    recommendation: "Never use CSS expressions. Use standard CSS properties instead and sanitize any CSS that may come from user input.",
    recommendationCode: `// Instead of CSS expressions
// NEVER do this:
// element.style.cssText = "width: expression(alert('XSS'))";
// <div style="width: expression(alert('XSS'))"></div>

// Use standard CSS:
element.style.width = safeValue + 'px';

// If you need dynamic values, use JavaScript:
function updateElementWidth(element, value) {
  // Validate the value is a number
  const width = parseFloat(value);
  if (!isNaN(width) && width > 0) {
    element.style.width = width + 'px';
  }
}

// If you need to set complex CSS from user input:
import DOMPurify from 'dompurify';

function setElementStyle(element, css) {
  // Use DOMPurify to clean CSS
  const cleanProps = {};
  const tempDiv = document.createElement('div');
  tempDiv.style.cssText = DOMPurify.sanitize('x:y; ' + css);
  
  // Extract cleaned properties
  const style = tempDiv.style;
  for (let i = 0; i < style.length; i++) {
    const prop = style[i];
    cleanProps[prop] = style[prop];
  }
  
  // Apply cleaned properties
  Object.assign(element.style, cleanProps);
}`
  },
  // CSP bypass techniques
  {
    type: "cspBypass",
    regex: /document\.getElementsByTagName\s*\(\s*['"]script['"].*?\.appendChild\s*\(|document\.write\s*\(\s*(['"`])<script\s*src/ig,
    severity: "high" as const,
    title: "Potential CSP Bypass",
    description: "Dynamically adding script elements or using document.write with scripts may bypass CSP restrictions in some cases.",
    recommendation: "Use proper ways to load scripts, preferably at initial page load time, and ensure your CSP policies are correctly configured.",
    recommendationCode: `// Instead of dynamic script insertion:
// document.write('<script src="' + source + '"></script>');

// Proper script loading with checks:
function loadScript(src, callback) {
  // Validate the source URL
  if (!src.match(/^https:\/\/trusted-domain\.com\//)) {
    console.error('Untrusted script source');
    return;
  }
  
  // Create script element properly
  const script = document.createElement('script');
  script.async = true;
  
  // Add load event handler
  if (callback) {
    script.onload = callback;
  }
  
  // Set source after other properties and listeners
  script.src = src;
  
  // Append to document
  document.head.appendChild(script);
}

// Even better, use modern approaches like ES modules
import { feature } from './trusted-module.js';

// Or dynamic imports when needed
async function loadFeature() {
  try {
    const module = await import('./feature.js');
    module.initialize();
  } catch (err) {
    console.error('Failed to load module:', err);
  }
}`
  },
  // HTML attribute mutations
  {
    type: "htmlAttributeMutation",
    regex: /\.setAttribute\s*\(\s*(['"`])(?:on\w+|srcdoc|style|formaction)\1\s*,\s*(?!['"]{2})/g,
    severity: "high" as const,
    title: "Dangerous HTML Attribute Mutation",
    description: "Setting security-sensitive attributes on HTML elements can lead to XSS vulnerabilities when user input is used.",
    recommendation: "Never set event handlers or security-sensitive attributes like 'srcdoc' or 'formaction' dynamically from user input.",
    recommendationCode: `// AVOID setting sensitive attributes from user input:
// element.setAttribute('onclick', userProvidedHandler);  // UNSAFE
// element.setAttribute('srcdoc', userProvidedHTML);      // UNSAFE
// element.setAttribute('style', userProvidedStyles);     // RISKY
// element.setAttribute('formaction', userProvidedURL);   // UNSAFE

// Instead, use proper event listeners:
element.addEventListener('click', function(e) {
  // Handle event safely with user data as a parameter, not as code
  safeHandler(userProvidedData);
});

// For iframe content, use explicit document.write with sanitized content:
const iframe = document.createElement('iframe');
document.body.appendChild(iframe);
const sanitizedHTML = DOMPurify.sanitize(userProvidedHTML);
iframe.contentDocument.open();
iframe.contentDocument.write(sanitizedHTML);
iframe.contentDocument.close();

// For styles, validate and sanitize:
const validatedStyles = {};
// Extract only safe properties
if (/^[0-9]+px$/.test(userInput)) {
  validatedStyles.width = userInput; // Only allow validated values
}`
  },
  // HTML5 postMessage without origin check
  {
    type: "postMessageNoOriginCheck",
    regex: /window\.addEventListener\s*\(\s*['"]message['"]\s*,\s*(?:function\s*\([^)]*\)|[^,]*)\s*(?:\{[^{}]*\}|=>(?:[^{}]|\{[^{}]*\}))/g,
    severity: "medium" as const,
    title: "Missing Origin Check in postMessage Handler",
    description: "Processing message events without checking the origin can lead to cross-origin attacks.",
    recommendation: "Always verify the origin of messages before processing them to ensure they come from trusted sources.",
    recommendationCode: `// UNSAFE: No origin check
// window.addEventListener('message', (event) => {
//   const data = event.data;
//   document.getElementById('output').innerHTML = data.message;
// });

// SECURE: With proper origin validation
window.addEventListener('message', (event) => {
  // ALWAYS check origin before processing messages
  const trustedOrigins = ['https://trusted-site.com', 'https://partner-site.org'];
  
  if (!trustedOrigins.includes(event.origin)) {
    console.error('Received message from untrusted origin:', event.origin);
    return; // Ignore messages from untrusted origins
  }
  
  // Now safe to process the message
  try {
    const data = typeof event.data === 'string' ? JSON.parse(event.data) : event.data;
    // Use safe DOM manipulation
    document.getElementById('output').textContent = data.message;
  } catch (e) {
    console.error('Error processing message:', e);
  }
});`
  },
  // Event handler injection
  {
    type: "eventHandlerInjection",
    regex: /\[\s*['"]on\w+['"]\s*\]\s*=|\.on\w+\s*=\s*(?!function|null|undefined|false)/g,
    severity: "high" as const,
    title: "Event Handler Injection Vector",
    description: "Assigning event handlers directly using user input is a common XSS vector that can execute arbitrary code.",
    recommendation: "Use addEventListener and pass functions instead of strings. Never assign event handlers using user-controlled data.",
    recommendationCode: `// AVOID these patterns:
// element.onclick = userProvidedCode;                // UNSAFE
// element['onclick'] = userProvidedCode;             // UNSAFE
// element.setAttribute('onclick', userProvidedCode); // UNSAFE

// INSTEAD, use proper event listeners:
element.addEventListener('click', function(event) {
  // Access user data here as a parameter
  handleClick(userProvidedData);
});

// If you need dynamic handlers:
const handlers = {
  'edit': function() { /* edit functionality */ },
  'delete': function() { /* delete functionality */ },
  'view': function() { /* view functionality */ }
};

// Then safely use the predefined handler:
const action = validateAction(userProvidedAction); // Validate to allowed values
if (handlers.hasOwnProperty(action)) {
  element.addEventListener('click', handlers[action]);
}`
  },
  // Dynamic property assignment using bracket notation (common evasion technique)
  {
    type: "dynamicPropertyAssignment",
    regex: /(?:window|document|location|localStorage|sessionStorage)\s*\[\s*(?:(?!['"]cookie['"])[^\]]*)\]\s*=\s*(?!null|undefined|false)/g,
    severity: "medium" as const,
    title: "Dynamic Global Property Assignment",
    description: "Using bracket notation to dynamically set properties on security-sensitive objects can lead to XSS or prototype pollution.",
    recommendation: "Avoid dynamically assigning properties to global objects, especially when the property name comes from user input.",
    recommendationCode: `// UNSAFE pattern:
// window[userProvidedProperty] = userProvidedValue;

// SAFER approach - use a restricted object for custom properties:
const safeStorage = {};

function setProperty(key, value) {
  // Validate key is allowed
  const allowedKeys = ['username', 'preferences', 'theme', 'language'];
  if (!allowedKeys.includes(key)) {
    console.error('Attempt to set disallowed property:', key);
    return false;
  }
  
  // Validate value if needed
  if (typeof value !== 'string' && typeof value !== 'number' && typeof value !== 'boolean') {
    console.error('Only primitive values allowed');
    return false;
  }
  
  // Now safe to store
  safeStorage[key] = value;
  return true;
}

// Usage:
setProperty('theme', userSelectedTheme);`
  },
  // Base64 execution vectors (common obfuscation technique)
  {
    type: "base64Execution",
    regex: /(?:eval|Function|setTimeout|setInterval)\s*\(\s*atob\s*\(|\(atob\(\s*['"][A-Za-z0-9+/=]+['"]\s*\)\s*\)/g,
    severity: "critical" as const,
    title: "Base64 Code Execution",
    description: "Using atob() to decode and execute Base64-encoded strings is a common technique to hide malicious code from security scanners.",
    recommendation: "Never execute code that comes from Base64-decoded strings, even if it seems harmless.",
    recommendationCode: `// NEVER do these:
// eval(atob(encodedScript));
// setTimeout(atob(encodedCommand), 100);
// new Function(atob(encodedCode))();

// For legitimate Base64 data:
function safelyDecodeBase64(encodedData) {
  try {
    // Decode but don't execute
    const decoded = atob(encodedData);
    
    // Log for debugging/transparency
    console.log('Decoded data:', decoded);
    
    // Process as data, not code
    return decoded;
  } catch (e) {
    console.error('Invalid Base64 data:', e);
    return null;
  }
}

// Then use the decoded data for non-executable purposes
const userData = safelyDecodeBase64(encodedUserData);
document.getElementById('profile').textContent = userData;`
  },
  // WebSockets without validation 
  {
    type: "unsafeWebSocket",
    regex: /new\s+WebSocket\s*\(\s*([^)]*)\)/g,
    severity: "medium" as const,
    title: "Potentially Unsafe WebSocket Connection",
    description: "Creating WebSocket connections without proper URL validation or message handling can lead to data injection vulnerabilities.",
    recommendation: "Validate WebSocket URLs and sanitize all incoming messages before processing them.",
    recommendationCode: `// Instead of:
// const ws = new WebSocket(userProvidedUrl);

// Validate the WebSocket URL first:
function createSecureWebSocket(url) {
  // Ensure the URL is from an allowed domain
  const allowedDomains = ['api.our-service.com', 'websocket.trusted-source.org'];
  
  try {
    const wsUrl = new URL(url);
    if (!allowedDomains.includes(wsUrl.hostname)) {
      console.error('WebSocket connection to untrusted host rejected');
      return null;
    }
    
    // Now it's safer to connect
    const ws = new WebSocket(url);
    
    // Set up message handling
    ws.addEventListener('message', (event) => {
      try {
        // Validate and sanitize the data before using it
        const data = JSON.parse(event.data);
        
        // Safe handling of the data
        processValidatedWebSocketData(data);
      } catch (e) {
        console.error('Invalid WebSocket message:', e);
      }
    });
    
    return ws;
  } catch (e) {
    console.error('Invalid WebSocket URL:', e);
    return null;
  }
}`
  },
  // URL API misuse
  {
    type: "urlAPIVulnerability",
    regex: /URL\.createObjectURL\s*\(\s*(?:user|input|data|file|blob|new Blob)/gi,
    severity: "high" as const,
    title: "Unsafe Use of URL.createObjectURL",
    description: "Creating object URLs from user-supplied data can lead to XSS and data exfiltration vulnerabilities.",
    recommendation: "Validate file types and sanitize content before creating object URLs. Always revoke URLs after use.",
    recommendationCode: `// UNSAFE pattern:
// const objectUrl = URL.createObjectURL(userBlob);
// frame.src = objectUrl;

// SAFER approach:
function createSafeObjectURL(file) {
  // Validate file is of allowed type
  const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf'];
  
  if (!allowedTypes.includes(file.type)) {
    console.error('Unsupported file type:', file.type);
    return null;
  }
  
  // Create the URL
  const objectUrl = URL.createObjectURL(file);
  
  // Set up automatic revocation
  setTimeout(() => {
    URL.revokeObjectURL(objectUrl);
  }, 30000); // Revoke after 30 seconds or when no longer needed
  
  return objectUrl;
}

// Usage:
const displayImage = (file) => {
  const safeUrl = createSafeObjectURL(file);
  if (safeUrl) {
    const img = document.createElement('img');
    img.onload = () => URL.revokeObjectURL(safeUrl); // Revoke immediately after load
    img.src = safeUrl;
    document.getElementById('preview').appendChild(img);
  }
};`
  },
  // client-side prototype pollution vectors
  {
    type: "prototypeContamination",
    regex: /(?:Object\.prototype|__proto__|prototype)\s*\[\s*(['"`][^'"`]+['"`])\s*\]\s*=|\[\s*['"]__proto__['"]\s*\]\s*\[\s*(['"][^'"]+['"])\s*\]\s*=/g,
    severity: "high" as const,
    title: "Prototype Pollution Vector",
    description: "Modifying Object.prototype or using __proto__ can lead to prototype pollution vulnerabilities that enable XSS attacks.",
    recommendation: "Never modify built-in prototypes. Use Object.create(null) for safe dictionaries and implement secure object merge functions.",
    recommendationCode: `// NEVER do these:
// Object.prototype[userKey] = userValue;
// obj.__proto__[userKey] = userValue;
// obj["__proto__"]["toString"] = maliciousFunction;

// SAFER object operations:

// 1. Use Object.create(null) for dictionaries
const safeDict = Object.create(null);
safeDict[userKey] = userValue; // No prototype to pollute

// 2. Safe object merging function
function safeObjectMerge(target, source) {
  // Skip __proto__ and prototype
  const sanitizedSource = Object.entries(source)
    .filter(([key]) => {
      return key !== '__proto__' && 
             key !== 'constructor' && 
             key !== 'prototype';
    })
    .reduce((obj, [key, value]) => {
      // For nested objects, recursively sanitize
      if (value && typeof value === 'object') {
        obj[key] = safeObjectMerge(
          target[key] && typeof target[key] === 'object' ? target[key] : {}, 
          value
        );
      } else {
        obj[key] = value;
      }
      return obj;
    }, {});
  
  // Now safely merge
  return { ...target, ...sanitizedSource };
}

// Usage:
const mergedConfig = safeObjectMerge(defaultConfig, userConfig);`
  },
  // Mutation observer usage (more advanced detection of DOM manipulation)
  {
    type: "unsafeMutationObserver",
    regex: /new\s+MutationObserver\s*\(\s*(?:function\s*\([^)]*\)|[^,]*)\s*\)\s*\.observe\s*\(\s*document(?:\.body|\.documentElement)?/g,
    severity: "medium" as const,
    title: "Potentially Unsafe MutationObserver Usage",
    description: "MutationObservers that watch the entire document can trigger on malicious DOM mutations, which can lead to security issues if not properly validated.",
    recommendation: "Use MutationObservers on specific elements and validate changes to prevent unwanted behavior.",
    recommendationCode: `// RISKY pattern:
// new MutationObserver(callback).observe(document, { 
//   childList: true, 
//   subtree: true 
// });

// SAFER approach:
// 1. Observe specific container elements, not the entire document
const secureContainer = document.getElementById('safe-dynamic-content');

// 2. Define careful validation in the callback
const observer = new MutationObserver((mutations) => {
  for (const mutation of mutations) {
    // Check for added nodes
    if (mutation.type === 'childList' && mutation.addedNodes.length) {
      // Validate each added node
      mutation.addedNodes.forEach(node => {
        if (node.nodeType === Node.ELEMENT_NODE) {
          // Remove unsafe elements or attributes
          sanitizeElement(node);
        }
      });
    }
  }
});

// Helper to sanitize elements
function sanitizeElement(element) {
  // Remove script tags entirely
  if (element.tagName === 'SCRIPT') {
    element.remove();
    return;
  }
  
  // Remove dangerous attributes
  ['onclick', 'onerror', 'onload', 'onmouseover'].forEach(attr => {
    if (element.hasAttribute(attr)) {
      element.removeAttribute(attr);
    }
  });
  
  // Check src attributes
  if (element.hasAttribute('src')) {
    const src = element.getAttribute('src');
    if (src.startsWith('javascript:') || src.startsWith('data:')) {
      element.removeAttribute('src');
    }
  }
  
  // Recursively check children
  Array.from(element.children).forEach(sanitizeElement);
}

// Start observing a specific container
observer.observe(secureContainer, { 
  childList: true, 
  subtree: true 
});`
  },
  // Meta tag injection
  {
    type: "metaTagInjection",
    regex: /createElement\s*\(\s*['"]meta['"][^;]*(?:\.content\s*=|\.setAttribute\s*\(\s*(?:['"]content['"]|['"]http-equiv['"]))[^;]*(?:get|location|url|parameter|param|query|search|hash|user)/gi,
    severity: "medium" as const,
    title: "Potential Meta Tag Injection",
    description: "Dynamically creating meta tags with user-controlled content can lead to client-side redirects or influence browser behavior.",
    recommendation: "Validate all meta tag content and attributes rigorously before adding to the document.",
    recommendationCode: `// UNSAFE pattern:
// const meta = document.createElement('meta');
// meta.setAttribute('http-equiv', 'refresh');
// meta.setAttribute('content', '0;url=' + userProvidedUrl);
// document.head.appendChild(meta);

// SAFER approach:
function safelyAddMetaTag(httpEquiv, content) {
  // Validate http-equiv is allowed
  const allowedHttpEquivs = ['content-type', 'default-style', 'x-ua-compatible'];
  if (!allowedHttpEquivs.includes(httpEquiv.toLowerCase())) {
    console.error('Prohibited meta http-equiv value:', httpEquiv);
    return null;
  }
  
  // For refresh http-equiv, validate the URL
  if (httpEquiv.toLowerCase() === 'refresh' && content.includes('url=')) {
    const urlMatch = /url=([^;,\s]+)/.exec(content);
    if (urlMatch) {
      const url = urlMatch[1];
      // Validate URL is from allowed domains
      const allowedDomains = ['example.com', 'trusted-site.org'];
      try {
        const parsedUrl = new URL(url);
        if (!allowedDomains.includes(parsedUrl.hostname)) {
          console.error('Meta refresh to untrusted domain:', parsedUrl.hostname);
          return null;
        }
      } catch (e) {
        console.error('Invalid URL in meta refresh:', url);
        return null;
      }
    }
  }
  
  // Create and add the meta tag
  const meta = document.createElement('meta');
  meta.setAttribute('http-equiv', httpEquiv);
  meta.setAttribute('content', content);
  document.head.appendChild(meta);
  return meta;
}`
  },
  // JavaScript source mapping exposure
  {
    type: "sourceMapExposure",
    regex: /\/\/# sourceMappingURL=\S+\.map(?!\s*$)/,
    severity: "low" as const,
    title: "Source Map Exposure in Production",
    description: "Exposing source maps in production can reveal sensitive implementation details and make the application more vulnerable to attacks.",
    recommendation: "Remove source map references in production builds to prevent revealing source code structure to potential attackers.",
    recommendationCode: `// Development build configuration
const devConfig = {
  // ... other config
  devtool: 'source-map', // Enables source maps for debugging
};

// Production build configuration
const prodConfig = {
  // ... other config
  devtool: false, // Disables source maps for production
};

// In your build script:
const config = process.env.NODE_ENV === 'production' ? prodConfig : devConfig;

// For webpack, you can also use terser to remove sourceMappingURL comments:
// In webpack.config.js for production:
const TerserPlugin = require('terser-webpack-plugin');

module.exports = {
  // ... other config
  optimization: {
    minimizer: [
      new TerserPlugin({
        terserOptions: {
          compress: {
            // ... other options
          },
          output: {
            comments: false, // Removes sourceMappingURL comments
          },
        },
      }),
    ],
  },
}`
  },
  // DOM-based open redirect
  {
    type: "domBasedOpenRedirect",
    regex: /(?:window\.location|location|document\.location|self\.location|top\.location|parent\.location)\s*=\s*(?!['"]https?:\/\/[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+)[^;]*/g,
    severity: "medium" as const,
    title: "DOM-Based Open Redirect",
    description: "Setting location without proper validation can lead to open redirect vulnerabilities that enable phishing attacks.",
    recommendation: "Always validate URLs before using them for redirection, ensuring they point to trusted domains.",
    recommendationCode: `// UNSAFE patterns:
// window.location = userProvidedUrl;
// location.href = params.get('redirect');
// document.location = getRedirectUrl();

// SAFER approach:
function safeRedirect(url) {
  // 1. Check if it's a relative URL (starts with / or ./)
  if (/^(\\/|\\.\\/|\\.\\.\\/)/.test(url)) {
    // Relative URLs are safe to redirect to
    window.location.href = url;
    return;
  }
  
  // 2. For absolute URLs, validate the domain
  try {
    const parsedUrl = new URL(url);
    
    // Check against allowlist of trusted domains
    const trustedDomains = [
      'example.com',
      'sub.example.com',
      'trusted-partner.org'
    ];
    
    // Check if the domain or any parent domain is trusted
    let domain = parsedUrl.hostname;
    const isDomainTrusted = trustedDomains.some(trusted => {
      return domain === trusted || domain.endsWith('.' + trusted);
    });
    
    if (isDomainTrusted) {
      // Ensure protocol is http or https
      if (parsedUrl.protocol === 'http:' || parsedUrl.protocol === 'https:') {
        window.location.href = url;
        return;
      }
    }
  } catch (e) {
    // URL parsing failed, don't redirect
    console.error('Invalid redirect URL:', url);
  }
  
  // If we get here, the redirect wasn't safe
  console.error('Unsafe redirect blocked:', url);
  // Redirect to default page instead
  window.location.href = '/home';
}`
  },
  // Anchor href with dangerous URL
  {
    type: "dangerousAnchorHref",
    regex: /\.href\s*=\s*(?!['"](?:https?:|mailto:|tel:|\/|#|\.\/))(?!\s*(?:DOMPurify|purify|sanitize|filter)\s*\()/ig,
    severity: "medium" as const,
    title: "Potentially Dangerous Link Target",
    description: "Setting href attributes without proper validation can lead to javascript: URI or data: URI based XSS attacks.",
    recommendation: "Validate all URLs before setting as href attributes. Ensure they use safe protocols like http:, https:, mailto:, or tel:.",
    recommendationCode: `// UNSAFE patterns:
// link.href = userInput;
// document.getElementById('download').href = getFileUrl(fileName);

// SAFER approach:
function setLinkUrl(linkElement, url) {
  // Function to validate URL safety
  function isUrlSafe(url) {
    // Safe if it's relative
    if (url.startsWith('/') || url.startsWith('./') || url.startsWith('../')) {
      return true;
    }
    
    // Check for safe protocols
    const safeProtocols = ['http:', 'https:', 'mailto:', 'tel:'];
    try {
      const parsedUrl = new URL(url);
      return safeProtocols.includes(parsedUrl.protocol);
    } catch (e) {
      // If parsing fails, it's not a valid URL
      return false;
    }
  }
  
  // Remove dangerous protocols
  function sanitizeUrl(url) {
    // Simple cleaning for javascript: and data: URIs
    if (/^(?:javascript|data|vbscript|file):/i.test(url)) {
      return '#'; // Replace with harmless fragment
    }
    return url;
  }
  
  // Check and set the URL
  if (isUrlSafe(url)) {
    linkElement.href = url;
  } else {
    console.error('Unsafe URL blocked:', url);
    linkElement.href = '#'; // Set to safe default
    // Optionally disable the link
    linkElement.style.pointerEvents = 'none';
    linkElement.style.color = 'gray';
    linkElement.title = 'Link disabled - unsafe URL';
  }
}`
  },
  // Dynamic script creation without integrity checks
  {
    type: "dynamicScriptWithoutIntegrity",
    regex: /document\.createElement\s*\(\s*['"]script['"](?![^]*integrity).*?\.src\s*=\s*(?!['"]https:\/\/)/g,
    severity: "low" as const,
    title: "Dynamic Script Without Integrity Checks",
    description: "Creating script elements without subresource integrity checks can lead to supply chain attacks if the source is compromised.",
    recommendation: "Use Subresource Integrity (SRI) checks when loading external scripts to ensure they haven't been tampered with.",
    recommendationCode: `// UNSAFE pattern:
// const script = document.createElement('script');
// script.src = 'https://third-party-cdn.com/library.js';
// document.head.appendChild(script);

// SAFER approach with SRI:
function loadScriptWithIntegrity(src, integrity) {
  return new Promise((resolve, reject) => {
    const script = document.createElement('script');
    
    // Set integrity and crossorigin attributes
    if (integrity && src.startsWith('https://')) {
      script.integrity = integrity;
      script.crossOrigin = 'anonymous';
    } else if (!src.startsWith('https://')) {
      console.warn('Non-HTTPS script source detected');
    } else if (!integrity) {
      console.warn('Missing integrity hash for external script');
    }
    
    // Set up load/error handlers
    script.onload = () => resolve(script);
    script.onerror = () => reject(new Error(\`Failed to load script: \${src}\`));
    
    // Set source last (after event handlers)
    script.src = src;
    
    // Add to document
    document.head.appendChild(script);
  });
}

// Usage:
loadScriptWithIntegrity(
  'https://cdn.example.com/library.js',
  'sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC'
).then(() => {
  console.log('Script loaded successfully!');
}).catch(error => {
  console.error('Script load failed:', error);
});

// To generate integrity hashes for your scripts:
// 1. Use a tool like https://www.srihash.org/
// 2. Or generate via command line:
//    cat library.js | openssl dgst -sha384 -binary | openssl base64 -A`
  },
  // Insecure randomness
  {
    type: "insecureRandomness",
    regex: /Math\.random\s*\(\s*\)(?:(?!\.toString).)*(password|token|secret|key|auth|crypt)/gi,
    severity: "medium" as const,
    title: "Insecure Randomness for Security-Critical Values",
    description: "Using Math.random() for security-sensitive values like tokens or passwords creates predictable values vulnerable to attack.",
    recommendation: "Use crypto.getRandomValues() or window.crypto.subtle.generateKey() for security-critical random values.",
    recommendationCode: `// UNSAFE patterns:
// const token = Math.random().toString(36).substring(2);
// const tempPassword = Math.random().toString(16).substring(2, 10);

// SAFER approaches:
// 1. For random tokens/IDs:
function generateSecureToken(length = 32) {
  // Create a typed array of required length
  const randomArray = new Uint8Array(length);
  
  // Fill with cryptographically strong random values
  window.crypto.getRandomValues(randomArray);
  
  // Convert to string (various options)
  // Option 1: Hex encoding
  return Array.from(randomArray)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
    
  // Option 2: Base64 encoding
  // return btoa(String.fromCharCode.apply(null, randomArray))
  //   .replace(/\\+/g, '-')
  //   .replace(/\\//g, '_')
  //   .replace(/=/g, '');
}

// 2. For cryptographic keys:
async function generateEncryptionKey() {
  // Generate a proper cryptographic key
  const key = await window.crypto.subtle.generateKey(
    {
      name: 'AES-GCM',
      length: 256
    },
    true, // extractable
    ['encrypt', 'decrypt']
  );
  
  return key;
}

// Usage:
const secureToken = generateSecureToken();
document.getElementById('csrf-token').value = secureToken;`
  },
  // Reflected data injection
  {
    type: "reflectedDataInjection",
    regex: /(?:document\.write|\.innerHTML|\.outerHTML)\s*\(\s*(?:.*?(?:location|window\.location|document\.URL|document\.documentURI|document\.referrer|document\.location)\.(?:hash|search|href|pathname)|.*?(?:URLSearchParams|url\.searchParams)\.get)/g,
    severity: "high" as const,
    title: "Reflected Data Injection",
    description: "Directly writing URL parameters to the DOM without sanitization enables reflected XSS attacks.",
    recommendation: "Always sanitize URL parameters before inserting them into the DOM. Use textContent for text nodes or a proper sanitization library for HTML.",
    recommendationCode: `// UNSAFE patterns:
// document.write(location.search.substring(1)); // Directly writing query params
// element.innerHTML = new URLSearchParams(location.search).get('message');

// SAFER approaches:
// Option 1: Use textContent for safe text display
const params = new URLSearchParams(window.location.search);
const message = params.get('message');
if (message) {
  document.getElementById('message-container').textContent = message;
}

// Option 2: For HTML content, use proper sanitization
import DOMPurify from 'dompurify';

const params = new URLSearchParams(window.location.search);
const htmlContent = params.get('content');
if (htmlContent) {
  // Sanitize the HTML before insertion
  const sanitizedHtml = DOMPurify.sanitize(htmlContent, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'ul', 'ol', 'li'],
    ALLOWED_ATTR: ['href', 'target']
  });
  document.getElementById('content-container').innerHTML = sanitizedHtml;
}`
  },
  // Dangerous innerHTML usage with variables
  {
    type: "dangerousInnerHTMLWithVariable",
    regex: /(?:\.innerHTML|\.outerHTML)\s*=\s*(?!['"`]\s*(?:<div|<span|<p|<h1|<a|<ul|<button|<img)[^+]*['"`]\s*\+)/g,
    severity: "high" as const,
    title: "Potentially Dangerous innerHTML Assignment",
    description: "Setting innerHTML/outerHTML with variables or concatenated strings can lead to XSS vulnerabilities if the input isn't properly sanitized.",
    recommendation: "Use textContent for text or sanitize HTML content before setting innerHTML. Consider using DOM methods like createElement for more complex structures.",
    recommendationCode: `// UNSAFE patterns:
// element.innerHTML = userProvidedData;
// element.innerHTML = "<div>" + message + "</div>";

// SAFER approaches:
// Option 1: For text content
element.textContent = userProvidedData;

// Option 2: For simple HTML structures, use DOM methods
function safelyCreateElement(message) {
  const div = document.createElement('div');
  div.className = 'message';
  
  const strong = document.createElement('strong');
  strong.textContent = 'Message: ';
  
  const span = document.createElement('span');
  span.textContent = message; // Safely set as text
  
  div.appendChild(strong);
  div.appendChild(span);
  
  return div;
}

// Usage:
const messageElement = safelyCreateElement(userMessage);
container.appendChild(messageElement);

// Option 3: When you need to insert HTML, use sanitization
import DOMPurify from 'dompurify';

function setHTML(element, htmlContent) {
  // Configure DOMPurify
  const sanitizedHTML = DOMPurify.sanitize(htmlContent, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'span', 'p', 'a', 'ul', 'ol', 'li'],
    ALLOWED_ATTR: ['href', 'class', 'id', 'target']
  });
  
  // Now safe to use innerHTML
  element.innerHTML = sanitizedHTML;
}`
  },
  // Insecure DOMParser usage
  {
    type: "insecureDOMParser",
    regex: /(?:new\s+DOMParser\s*\(\s*\)\.parseFromString|\.parseFromString)\s*\(\s*(?!['"]\s*<)/g,
    severity: "medium" as const,
    title: "Insecure DOMParser Usage",
    description: "Using DOMParser with unsanitized input can introduce XSS vulnerabilities when the parsed content is added to the live DOM.",
    recommendation: "Sanitize input before parsing it with DOMParser, especially when extracting elements to add to the live DOM.",
    recommendationCode: `// UNSAFE pattern:
// const parser = new DOMParser();
// const doc = parser.parseFromString(userProvidedHTML, 'text/html');
// document.body.appendChild(doc.body.firstChild);

// SAFER approach:
import DOMPurify from 'dompurify';

function safelyParseAndUseHTML(html) {
  // First sanitize the HTML
  const sanitizedHTML = DOMPurify.sanitize(html, {
    ALLOWED_TAGS: ['div', 'span', 'p', 'h1', 'h2', 'h3', 'ul', 'ol', 'li', 'a'],
    ALLOWED_ATTR: ['href', 'class', 'id', 'style']
  });
  
  // Then parse it
  const parser = new DOMParser();
  const doc = parser.parseFromString(sanitizedHTML, 'text/html');
  
  // Now it's safer to use in the live DOM
  return doc.body.firstChild;
}

// Usage:
const parsedElement = safelyParseAndUseHTML(userHTML);
if (parsedElement) {
  document.getElementById('container').appendChild(parsedElement);
}`
  },
  // DOM Clobbering via ID attribute
  {
    type: "domClobberingViaID",
    regex: /\.getElementById\s*\(\s*(?!['"](?:[a-zA-Z0-9_-]+)['"]\s*\))/g,
    severity: "medium" as const,
    title: "Potential DOM Clobbering Vulnerability",
    description: "Using getElementById with variable inputs can be exploited via DOM clobbering attacks, where attackers inject elements with controlled IDs.",
    recommendation: "Use constant, hardcoded IDs with getElementById or validate ID inputs against a strict allowlist.",
    recommendationCode: `// UNSAFE patterns:
// const element = document.getElementById(userProvidedId);
// document.getElementById(params.get('section')).innerHTML = content;

// SAFER approaches:
// Option 1: Use hardcoded IDs (preferred)
const element = document.getElementById('user-profile');

// Option 2: If dynamic IDs are needed, validate against an allowlist
function getElementByValidatedId(id) {
  // Define allowed IDs
  const allowedIds = ['profile', 'settings', 'dashboard', 'messages'];
  
  // Validate the ID
  if (typeof id !== 'string' || !allowedIds.includes(id)) {
    console.error('Invalid or disallowed element ID:', id);
    return null;
  }
  
  return document.getElementById(id);
}

// Usage:
const section = getElementByValidatedId(sectionId);
if (section) {
  section.textContent = data;
}`
  },
  // JSON.parse vulnerability
  {
    type: "unsafeJSONParse",
    regex: /JSON\.parse\s*\(\s*(?!['"]|\{|\[)[^;,)]*/g,
    severity: "medium" as const,
    title: "Potentially Unsafe JSON.parse Usage",
    description: "Using JSON.parse with unsanitized user-controlled data can lead to prototype pollution and other injection vulnerabilities.",
    recommendation: "Validate JSON input before parsing and use JSON schema validation for complex structures.",
    recommendationCode: `// UNSAFE patterns:
// const data = JSON.parse(userInput);
// const config = JSON.parse(localStorage.getItem('config'));

// SAFER approaches:
// Option 1: Add validation and error handling
function safeJsonParse(jsonString, defaultValue = {}) {
  try {
    if (typeof jsonString !== 'string') {
      return defaultValue;
    }
    
    // Optional: simple validation for very basic JSON format
    if (!jsonString.match(/^\\s*({|\\[)/)) {
      console.error('Invalid JSON format detected');
      return defaultValue;
    }
    
    const result = JSON.parse(jsonString);
    
    // Simple prototype pollution protection
    if (result && typeof result === 'object' && result.__proto__) {
      delete result.__proto__;
    }
    
    return result;
  } catch (e) {
    console.error('JSON parsing failed:', e);
    return defaultValue;
  }
}

// Option 2: Using JSON schema validation for more control
// npm install ajv
import Ajv from 'ajv';

function validateJsonWithSchema(json, schema) {
  const ajv = new Ajv();
  const validate = ajv.compile(schema);
  
  let data;
  try {
    data = (typeof json === 'string') ? JSON.parse(json) : json;
  } catch (e) {
    console.error('Invalid JSON:', e);
    return null;
  }
  
  const valid = validate(data);
  if (!valid) {
    console.error('Schema validation failed:', validate.errors);
    return null;
  }
  
  return data;
}

// Usage example:
const userSchema = {
  type: 'object',
  properties: {
    id: { type: 'number' },
    name: { type: 'string' },
    email: { type: 'string', format: 'email' }
  },
  required: ['id', 'name', 'email'],
  additionalProperties: false // Prevents extra properties
};

const userData = validateJsonWithSchema(userInputJSON, userSchema);
if (userData) {
  // Safe to use the data
  processUser(userData);
}`
  },
  // XSS in template literals
  {
    type: "xssInTemplateLiterals",
    regex: /`(?:[^`]*\$\{[^}]*(?:user|input|params|query|search|config|data|form)[^}]*\}[^`]*)+`(?=\s*[\.,;]?\s*(?:innerHTML|outerHTML|document\.write|\.insertAdjacentHTML))/g,
    severity: "high" as const,
    title: "XSS in Template Literals",
    description: "Using template literals with user-controlled data directly for HTML can lead to XSS vulnerabilities.",
    recommendation: "Sanitize data before using it in template literals that generate HTML, or use textContent instead of innerHTML.",
    recommendationCode: `// UNSAFE patterns:
// element.innerHTML = \`<div>Hello, \${userName}!</div>\`;
// container.innerHTML = \`
//   <article>
//     <h2>\${article.title}</h2>
//     <div class="content">\${article.body}</div>
//   </article>
// \`;

// SAFER approaches:
// Option 1: Sanitize data in template literals
import DOMPurify from 'dompurify';

function safeTemplate(template, data) {
  // Process template with sanitized values
  const html = template.replace(/\\{\\{([^}]+)\\}\\}/g, (match, key) => {
    const value = data[key.trim()];
    return value ? DOMPurify.sanitize(value) : '';
  });
  
  return html;
}

// Usage:
const template = \`
  <article>
    <h2>{{title}}</h2>
    <div class="content">{{body}}</div>
  </article>
\`;

const html = safeTemplate(template, {
  title: articleTitle,
  body: articleBody
});

container.innerHTML = html;

// Option 2: Build DOM safely instead of using innerHTML
function renderArticle(article) {
  const articleEl = document.createElement('article');
  
  const titleEl = document.createElement('h2');
  titleEl.textContent = article.title;
  
  const contentEl = document.createElement('div');
  contentEl.className = 'content';
  contentEl.textContent = article.body;
  
  articleEl.appendChild(titleEl);
  articleEl.appendChild(contentEl);
  
  return articleEl;
}

// Usage:
const articleElement = renderArticle({
  title: articleTitle,
  body: articleBody
});

container.appendChild(articleElement);`
  }
];
