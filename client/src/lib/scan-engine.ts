import { ScanResult, Vulnerability } from "@shared/schema";
import { v4 as uuidv4 } from "uuid";

// Patterns to detect XSS vulnerabilities
const patterns = [
  {
    type: "innerHTML",
    regex: /\.innerHTML\s*=\s*([^;]*)/g,
    severity: "critical",
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
    severity: "critical",
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
    severity: "high",
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
    severity: "high",
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
    severity: "medium",
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
    severity: "critical",
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
    severity: "high",
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
    severity: "medium",
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
  }
];

function findVulnerabilities(code: string): Vulnerability[] {
  const vulnerabilities: Vulnerability[] = [];

  patterns.forEach(pattern => {
    const regex = pattern.regex;
    regex.lastIndex = 0; // Reset regex state

    let match;
    while ((match = regex.exec(code)) !== null) {
      const matchedCode = match[0];
      // Get a bit of context around the vulnerability
      const startIndex = Math.max(0, match.index - 50);
      const endIndex = Math.min(code.length, match.index + matchedCode.length + 100);
      
      // Extract the code snippet with context
      const codeSnippet = code.substring(startIndex, endIndex);
      
      const vulnerability: Vulnerability = {
        id: uuidv4(),
        type: pattern.type,
        severity: pattern.severity as any,
        title: pattern.title,
        description: pattern.description,
        code: codeSnippet,
        recommendation: pattern.recommendation,
        recommendationCode: pattern.recommendationCode,
      };
      vulnerabilities.push(vulnerability);
    }
  });

  return vulnerabilities;
}

export function scanCode(code: string): ScanResult {
  const vulnerabilities = findVulnerabilities(code);
  
  // Count vulnerabilities by severity
  const summaryCounts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0, 
    info: 0
  };
  
  vulnerabilities.forEach(v => {
    summaryCounts[v.severity]++;
  });
  
  // Calculate the number of passed checks
  const totalChecks = patterns.length;
  const uniqueVulnerabilityTypes = new Set(vulnerabilities.map(v => v.type));
  const passedChecks = totalChecks - uniqueVulnerabilityTypes.size;
  
  return {
    vulnerabilities,
    summary: {
      ...summaryCounts,
      passedChecks,
    },
    scannedAt: new Date().toISOString(),
  };
}
