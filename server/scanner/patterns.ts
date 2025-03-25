/**
 * Advanced XSS vulnerability patterns to check for in JavaScript code
 * Each pattern includes detailed descriptions, severity ratings, and secure code recommendations
 */
export const scanPatterns = [
  // DOM-based XSS vulnerabilities
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
    regex: /\.insertAdjacentHTML\s*\(/g,
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
    regex: /document\.write\s*\(/g,
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
    regex: /document\.writeln\s*\(/g,
    severity: "high" as const,
    title: "Unsafe document.writeln() Usage",
    description: "Similar to document.write(), document.writeln() can lead to XSS vulnerabilities when used with user input.",
    recommendation: "Avoid document.writeln() and use safer DOM manipulation methods.",
    recommendationCode: `// Instead of document.writeln(userInput), use:
const element = document.createElement('div');
element.textContent = userInput + '\\n';
document.body.appendChild(element);`
  },

  // Code evaluation vulnerabilities
  {
    type: "eval",
    regex: /eval\s*\(/g,
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
    regex: /new\s+Function\s*\(/g,
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
    regex: /setTimeout\s*\(\s*['"`]([^'"`]*)['"`]/g,
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
    regex: /setInterval\s*\(\s*['"`]([^'"`]*)['"`]/g,
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

  // URL-based vulnerabilities
  {
    type: "setAttribute",
    regex: /\.setAttribute\s*\(\s*['"](?:href|src|action|formaction|data|href|xlink:href)['"]\s*,\s*([^)]*)\)/g,
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
    regex: /(?:location\.href|location\.search|location\.hash|location\.pathname)\s*=\s*([^;]*)/g,
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
    regex: /JSON\.parse\s*\([^)]*\)/g,
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
  // Parse the content and render it as React components
  // This depends on what exactly you're trying to achieve
  return <div>{content}</div>;
}`
  },
  {
    type: "domParser",
    regex: /(?:new\s+DOMParser\(\)\.parseFromString|createContextualFragment)\s*\(/g,
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
  }
];
