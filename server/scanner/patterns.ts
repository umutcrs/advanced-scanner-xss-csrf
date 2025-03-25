/**
 * XSS vulnerability patterns to check for in JavaScript code
 */
export const scanPatterns = [
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
    type: "setAttribute",
    regex: /\.setAttribute\s*\(\s*['"]href['"]\s*,\s*([^)]*)\)/g,
    severity: "high" as const,
    title: "Unsafe setAttribute Usage",
    description: "Unvalidated user input in URL attribute could allow javascript: protocol exploits and other URL-based attacks.",
    recommendation: "Validate URLs and ensure they don't begin with javascript: or data: protocols before using them in attributes.",
    recommendationCode: `function createLink() {
  const url = document.getElementById('url-input').value;
  
  // Validate URL
  const isValid = /^(https?:\\/\\/|\\/|\\.\\/|\\.\\.\\/)/i.test(url);
  if (!isValid) {
    console.error("Invalid URL detected");
    return;
  }
  
  const element = document.createElement('a');
  element.setAttribute('href', url);
  element.textContent = 'Click me'; // Use textContent, not innerHTML
  document.body.appendChild(element);
}`
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
    type: "scriptElement",
    regex: /document\.createElement\s*\(\s*['"]script['"]\s*\)/g,
    severity: "medium" as const,
    title: "Dynamic Script Loading",
    description: "Loading scripts from URLs controlled by user input can lead to execution of malicious code.",
    recommendation: "Never load scripts from untrusted sources. Use a whitelist approach to validate script URLs before loading.",
    recommendationCode: `function loadScript() {
  const scriptUrl = getParameterByName('src');
  
  // Whitelist of allowed script sources
  const allowedSources = [
    'https://trusted-cdn.com/',
    'https://your-own-domain.com/scripts/'
  ];
  
  // Check if URL is from allowed source
  const isAllowed = allowedSources.some(source => 
    scriptUrl.startsWith(source));
    
  if (!isAllowed) {
    console.error("Blocked loading script from untrusted source");
    return;
  }
  
  const script = document.createElement('script');
  script.src = scriptUrl;
  document.head.appendChild(script);
}`
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
    type: "locationHref",
    regex: /location\.href\s*=\s*([^;]*)/g,
    severity: "medium" as const,
    title: "Unsafe Location Assignment",
    description: "Setting location.href from user input can lead to javascript: URL exploits.",
    recommendation: "Validate URLs before setting location.href to prevent javascript: protocol injections.",
    recommendationCode: `function redirect(url) {
  // Validate URL format
  if (!/^(https?:|\/|\.\/|\.\.\/)/i.test(url)) {
    console.error("Invalid URL format");
    return;
  }
  
  // Now it's safe to redirect
  location.href = url;
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
  }
];
