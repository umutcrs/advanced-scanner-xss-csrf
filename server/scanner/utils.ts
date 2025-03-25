import { Vulnerability } from "@shared/schema";

/**
 * Extracts a code snippet from the source code, providing context around the vulnerability
 * @param code The full source code
 * @param index The starting index of the vulnerability
 * @param length The length of the vulnerable code
 * @returns A formatted code snippet with context
 */
export function extractCodeSnippet(code: string, index: number, length: number): string {
  // Find line numbers and context
  const lines = code.substring(0, index).split('\n');
  const lineNumber = lines.length;
  const columnNumber = lines[lines.length - 1]?.length + 1 || 0;
  
  // Find the line start and end indices
  let lineStartIndex = index;
  while (lineStartIndex > 0 && code[lineStartIndex - 1] !== '\n') {
    lineStartIndex--;
  }
  
  let lineEndIndex = index + length;
  while (lineEndIndex < code.length && code[lineEndIndex] !== '\n') {
    lineEndIndex++;
  }
  
  // Get additional context lines
  const contextLines = 2; // Number of lines to show before and after
  
  // Find start of context
  let contextStartIndex = lineStartIndex;
  let startLineCount = contextLines;
  while (startLineCount > 0 && contextStartIndex > 0) {
    contextStartIndex--;
    if (code[contextStartIndex] === '\n') {
      startLineCount--;
    }
  }
  if (contextStartIndex > 0) {
    contextStartIndex++; // Skip the newline character
  }
  
  // Find end of context
  let contextEndIndex = lineEndIndex;
  let endLineCount = contextLines;
  while (endLineCount > 0 && contextEndIndex < code.length) {
    if (code[contextEndIndex] === '\n') {
      endLineCount--;
    }
    contextEndIndex++;
  }
  
  // Extract the code snippet with context
  let codeSnippet = code.substring(contextStartIndex, contextEndIndex);
  
  // If we truncated the beginning, add ellipsis
  if (contextStartIndex > 0) {
    codeSnippet = "..." + codeSnippet;
  }
  
  // If we truncated the end, add ellipsis
  if (contextEndIndex < code.length) {
    codeSnippet = codeSnippet + "...";
  }
  
  return codeSnippet;
}

/**
 * Counts the number of vulnerabilities with a specific severity
 * @param vulnerabilities List of vulnerabilities
 * @param severity The severity to count
 * @returns The count of vulnerabilities with the specified severity
 */
export function countPatternMatches(vulnerabilities: Vulnerability[], severity: string): number {
  return vulnerabilities.filter(v => v.severity === severity).length;
}

/**
 * Formats a JavaScript code snippet with proper indentation
 * @param code The code to format
 * @returns Formatted code
 */
export function formatCodeSnippet(code: string): string {
  try {
    // Simple formatting: split by newlines and adjust indentation
    const lines = code.split('\n');
    let indent = 0;
    const formattedLines = lines.map(line => {
      // Count opening and closing braces for indentation
      const openBraces = (line.match(/{/g) || []).length;
      const closeBraces = (line.match(/}/g) || []).length;
      
      // Adjust indent for this line (closing braces affect the current line)
      if (closeBraces > 0) {
        indent = Math.max(0, indent - closeBraces);
      }
      
      // Apply indentation
      const formattedLine = '  '.repeat(indent) + line.trim();
      
      // Adjust indent for the next line (opening braces affect the next line)
      if (openBraces > 0) {
        indent += openBraces;
      }
      
      return formattedLine;
    });
    
    return formattedLines.join('\n');
  } catch (error) {
    // If formatting fails, return the original code
    return code;
  }
}

/**
 * Analyzes JavaScript code for data flow between user input sources and vulnerable sinks
 * This helps reduce false positives by confirming data flow from input to sink
 * @param code The JavaScript code to analyze
 * @param vulnerableIndices Array of indices where potential vulnerabilities were found
 * @returns Array of validated vulnerable indices where data flow is confirmed
 */
export function analyzeDataFlow(code: string, vulnerableIndices: Array<{index: number, length: number, type: string}>): Array<{index: number, length: number, type: string}> {
  // Common user input sources
  const userInputSources = [
    /document\.getElementById\([^)]+\)\.value/g,
    /document\.querySelector\([^)]+\)\.value/g,
    /getElementById\([^)]+\)\.value/g,
    /querySelector\([^)]+\)\.value/g,
    /\.(value|innerHTML|innerText|textContent)/g,
    /\bprompt\s*\(/g,
    /\blocation\.(href|search|hash|pathname)/g,
    /\$\.\s*(?:get|post)\s*\(/g,
    /fetch\s*\(/g,
    /XMLHttpRequest/g,
    /\bURL\s*\(/g,
    /localStorage\.getItem/g,
    /sessionStorage\.getItem/g
  ];
  
  const validatedVulnerabilities = [];
  
  for (const vul of vulnerableIndices) {
    // Skip small code blocks that are likely to be false positives
    if (vul.length < 3) continue;
    
    // Extract a larger context around the vulnerability (up to 5 lines before)
    const contextStartIndex = findContextStart(code, vul.index, 800);
    const contextCode = code.substring(contextStartIndex, vul.index + vul.length);
    
    // Check if any user input source is present in the context
    let hasUserInput = false;
    
    for (const sourceRegex of userInputSources) {
      sourceRegex.lastIndex = 0; // Reset regex state
      if (sourceRegex.test(contextCode)) {
        hasUserInput = true;
        break;
      }
    }
    
    // If user input is present or the vulnerability type is already high-risk
    // (like eval or innerHTML assignment), include it in validated results
    if (hasUserInput || 
        ['eval', 'innerHTML', 'outerHTML', 'documentWrite', 'insertAdjacentHTML', 'functionConstructor', 
        'setTimeout', 'setInterval', 'dangerouslySetInnerHTML'].includes(vul.type)) {
      validatedVulnerabilities.push(vul);
    }
  }
  
  return validatedVulnerabilities;
}

/**
 * Finds an appropriate starting point for context, looking for logical boundaries in code
 * @param code The full source code
 * @param index The index to start searching backward from
 * @param maxLookback Maximum number of characters to look back
 * @returns Index to start the context from
 */
function findContextStart(code: string, index: number, maxLookback: number): number {
  const minIndex = Math.max(0, index - maxLookback);
  
  // Try to find the start of a function or block that contains our vulnerability
  for (let i = index; i >= minIndex; i--) {
    // Look for function declarations, if/for/while statements, or assignments
    if (i > 0 && code[i - 1] === '{' && 
        /function|if|for|while|switch|=/.test(code.substring(Math.max(0, i - 20), i))) {
      return Math.max(0, i - 20);
    }
  }
  
  return minIndex;
}

/**
 * Analyzes the vulnerability and determines a confidence score (0-1)
 * to reduce false positives and improve result accuracy
 * @param code The full source code
 * @param match The RegExp match object
 * @param vulnType The type of vulnerability
 * @returns A confidence score between 0 and 1
 */
export function calculateConfidenceScore(code: string, match: RegExpExecArray, vulnType: string): number {
  // Base confidence by vulnerability type
  const baseConfidence: Record<string, number> = {
    // Critical severity - highest confidence
    "eval": 0.95,
    "indirectEval": 0.95,
    "functionConstructor": 0.95,
    "jsGlobalWithEval": 0.9,
    "innerHTML": 0.85,
    "outerHTML": 0.85,
    "dangerouslySetInnerHTML": 0.85,
    "scriptTextContent": 0.9,
    "setAttributeEvent": 0.85,
    "srcdocAssignment": 0.9,
    "angularBypassSecurityTrustHtml": 0.9,
    
    // High severity
    "insertAdjacentHTML": 0.75,
    "documentWrite": 0.75,
    "documentWriteLn": 0.75,
    "setTimeout": 0.75,
    "setInterval": 0.75,
    "setAttribute": 0.7,
    "scriptSrc": 0.8,
    "templateLiteralHtml": 0.75,
    "htmlFromConcatenation": 0.75,
    "unsafeJQueryHtml": 0.8,
    "documentCreateRange": 0.75,
    "eventHandlerProperty": 0.8,
    "iframeSrc": 0.7,
    "vueVBind": 0.7,
    
    // Medium severity
    "locationAssignment": 0.65,
    "locationHref": 0.65,
    "locationPropertyAssignment": 0.6,
    "aHref": 0.6,
    "objectData": 0.6,
    "postMessageOrigin": 0.65,
    "domParser": 0.6,
    "jsonParse": 0.55,
    "parseFromString": 0.6,
    "scriptElement": 0.65,
    "objectDefineProperty": 0.65,
    "documentCreateElement": 0.6,
    
    // Low severity
    "innerText": 0.45,
    "documentGetElementById": 0.4,
    "urlSearchParamsAppend": 0.4
  };
  
  // Start with the base confidence for this vulnerability type
  let confidence = baseConfidence[vulnType] || 0.5;
  
  // Extract a context around the match
  const contextStart = Math.max(0, match.index - 300);
  const contextEnd = Math.min(code.length, match.index + match[0].length + 300);
  const context = code.substring(contextStart, contextEnd);
  
  // Increase confidence if there's evidence of user input
  const userInputPatterns = [
    /user(?:Input|Data|Name|Content|Value|Id)/i,
    /input(?:Value|Data|Field|Text)/i,
    /value(?:From|Of|By)/i,
    /param(?:eter|Value|String)/i,
    /request\.(?:body|query|params)/i,
    /form(?:Data|Value|Input)/i,
    /\.(value|innerText|textContent)/,
    /document\.getElementById\([^)]+\)\.value/,
    /document\.querySelector\([^)]+\)\.value/,
    /\$\([\s\S]*?\)\.val\(\)/,
    /fetch\([\s\S]*?\)\.then/,
    /\$\.(get|post|ajax)\(/,
    /axios\.(get|post)\(/,
    /XMLHttpRequest/,
    /data(?:From|Value|Content)/i,
    /localStorage\.getItem/,
    /sessionStorage\.getItem/,
    /\bURL\b.*\blocation\b/,
    /\blocation\.(?:search|hash|href|pathname)/
  ];
  
  for (const pattern of userInputPatterns) {
    if (pattern.test(context)) {
      confidence += 0.15; // Higher increase for more specific evidence
      break;
    }
  }
  
  // Decrease confidence if there appears to be sanitization or validation
  const sanitizationPatterns = [
    /sanitize(?:Html|Input|Content|Value)/i,
    /escape(?:Html|String|Content|Value)/i,
    /encodeURI(?:Component)?/,
    /DOMPurify\.sanitize/,
    /\bfilter(?:Input|Content|Value|XSS)/i,
    /validate(?:Input|Content|Value|Url)/i,
    /purify(?:Html|Content|Input)/i,
    /html(?:Entities|Escape)/i,
    /is(?:Valid|Safe)(?:Input|Url|Content)/i,
    /check(?:For|If)(?:XSS|Injection|Malicious)/i,
    /remove(?:Dangerous|Unsafe|Malicious)/i,
    /clean(?:Input|Data|Content|Html)/i,
    /strip(?:Tags|Scripts|Unsafe)/i
  ];
  
  for (const pattern of sanitizationPatterns) {
    if (pattern.test(context)) {
      confidence -= 0.25; // Higher decrease for clear evidence of sanitization
      break;
    }
  }
  
  // Adjust confidence based on context specific to vulnerability type
  // For example, URL validations for URL-related vulnerabilities
  if (/href|src|url|location/.test(vulnType.toLowerCase())) {
    if (/https?:\/\/|isValidUrl|validateUrl|checkUrl/.test(context)) {
      confidence -= 0.1;
    }
  }
  
  // For DOM manipulation vulnerabilities, check for DOM safety patterns
  if (/innerHTML|outerHTML|dangerouslySetInnerHTML|document\.write/.test(vulnType)) {
    if (/createTextNode|textContent|innerText/.test(context)) {
      confidence -= 0.1;
    }
  }
  
  // Higher confidence if we see dangerous patterns nearby
  const dangerousPatterns = [
    /['"]\s*\+\s*(?:user|input|value|param)/i,  // String concatenation with user input
    /\${(?:[^{}]*?)(?:user|input|value|param)}/i, // Template literal with user input
    /(?:user|input|value|param)(?:[^;{]*?)['"]/i, // User input used in a string
    /JSON\.parse\((?:[^;]*?)(?:user|input|value|param)/i, // JSON.parse with user input
    /new\s+Function\((?:[^)]*?)(?:user|input|value|param)/i // Function constructor with user input
  ];
  
  for (const pattern of dangerousPatterns) {
    if (pattern.test(context)) {
      confidence += 0.1;
      break;
    }
  }
  
  // Decrease confidence for very small matches that might be false positives
  if (match[0].length < 5) {
    confidence -= 0.15;
  }
  
  // Decrease confidence for matches that appear in test/mock code
  if (/test|spec|mock|stub|fake|dummy|example/.test(context.toLowerCase())) {
    confidence -= 0.2;
  }
  
  // Decrease even more if it's in a comment or string literal
  if (isMostLikelyComment(code, match.index)) {
    confidence -= 0.6; // Almost certainly a false positive
  } else if (code.substring(Math.max(0, match.index - 200), match.index).includes("'") || 
             code.substring(Math.max(0, match.index - 200), match.index).includes('"') ||
             code.substring(Math.max(0, match.index - 200), match.index).includes('`')) {
    // Simple check if we're potentially inside a string
    confidence -= 0.3; // Likely a false positive, but could be building a string for eval
  }
  
  // Check execution context for certain vulnerability types that are context-sensitive
  if (["eval", "Function", "setTimeout", "setInterval"].includes(vulnType)) {
    // Higher confidence if these are used in event handlers or dynamic code generation
    if (/onclick|addEventListener|event|handler|dynamic|generate/.test(context)) {
      confidence += 0.1;
    }
  }
  
  // Ensure confidence is between 0 and 1
  return Math.max(0, Math.min(1, confidence));
}

/**
 * Checks if the code at a given index is within a comment
 * @param code The full source code
 * @param index The index to check
 * @returns Boolean indicating if the index is in a comment
 */
function isMostLikelyComment(code: string, index: number): boolean {
  // Check for line comment
  let lineStart = index;
  while (lineStart > 0 && code[lineStart - 1] !== '\n') {
    lineStart--;
  }
  
  const lineBeforeMatch = code.substring(lineStart, index);
  if (lineBeforeMatch.includes('//')) {
    return true;
  }
  
  // Check for block comment
  const blockCommentStart = code.lastIndexOf('/*', index);
  if (blockCommentStart !== -1) {
    const blockCommentEnd = code.indexOf('*/', blockCommentStart);
    if (blockCommentEnd === -1 || blockCommentEnd > index) {
      return true;
    }
  }
  
  return false;
}

/**
 * Improved version of the comment check that handles more edge cases
 * @param code The full source code
 * @param startIndex The start index of the potential vulnerability
 * @param endIndex The end index of the potential vulnerability
 * @returns Boolean indicating if the code section is inside a comment
 */
function isInsideComment(code: string, startIndex: number, endIndex: number): boolean {
  // First check if we're in a line comment
  let lineStart = startIndex;
  while (lineStart > 0 && code[lineStart - 1] !== '\n') {
    lineStart--;
  }
  
  const lineBeforeMatch = code.substring(lineStart, startIndex);
  if (lineBeforeMatch.includes('//')) {
    return true;
  }
  
  // Check if we're inside a block comment
  // Find the closest comment start and end before the vulnerability
  let pos = 0;
  let inComment = false;
  let lastCommentStart = -1;
  
  while (pos < endIndex) {
    // Look for comment start
    if (!inComment) {
      const nextCommentStart = code.indexOf('/*', pos);
      // If no more comment starts or comment starts after our position, we're done
      if (nextCommentStart === -1 || nextCommentStart >= endIndex) {
        break;
      }
      
      lastCommentStart = nextCommentStart;
      inComment = true;
      pos = nextCommentStart + 2; // Move past the comment start
    } 
    // Look for comment end
    else {
      const nextCommentEnd = code.indexOf('*/', pos);
      // If no comment end, the comment continues to the end of the file
      if (nextCommentEnd === -1) {
        return startIndex > lastCommentStart; // True if we're after comment start
      }
      
      // If comment ends before our vulnerability starts, keep looking
      if (nextCommentEnd < startIndex) {
        inComment = false;
        pos = nextCommentEnd + 2; // Move past the comment end
      } 
      // If comment overlaps with our vulnerability, we're in a comment
      else {
        return true;
      }
    }
  }
  
  // One last check - if we're in a comment and no end was found
  return inComment && startIndex > lastCommentStart;
}

/**
 * Checks if code at the given index is inside a string literal
 * @param code The full source code
 * @param index The index to check
 * @returns Boolean indicating if the index is in a string literal
 */
function isInsideStringLiteral(code: string, index: number): boolean {
  // Scan backward from the match looking for unclosed string delimiters
  let pos = index - 1;
  let inSingleQuote = false;
  let inDoubleQuote = false;
  let inTemplateLiteral = false;
  
  while (pos >= 0) {
    const char = code[pos];
    
    // Check for escaped characters
    if (char === '\\') {
      pos -= 2; // Skip the escaped character
      continue;
    }
    
    // Check for string boundaries
    if (!inDoubleQuote && !inTemplateLiteral && char === "'") {
      inSingleQuote = !inSingleQuote;
    } else if (!inSingleQuote && !inTemplateLiteral && char === '"') {
      inDoubleQuote = !inDoubleQuote;
    } else if (!inSingleQuote && !inDoubleQuote && char === '`') {
      inTemplateLiteral = !inTemplateLiteral;
    } 
    // If we hit a newline while in single/double quote, string likely ended
    // (template literals can span multiple lines)
    else if ((inSingleQuote || inDoubleQuote) && char === '\n') {
      inSingleQuote = false;
      inDoubleQuote = false;
    }
    
    pos--;
  }
  
  // If we're in any kind of string at the time we reach the match, it's in a string literal
  return inSingleQuote || inDoubleQuote || inTemplateLiteral;
}
