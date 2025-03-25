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
    "eval": 0.9,
    "innerHTML": 0.8,
    "outerHTML": 0.8,
    "insertAdjacentHTML": 0.7,
    "documentWrite": 0.7,
    "documentWriteLn": 0.7,
    "functionConstructor": 0.9,
    "setTimeout": 0.7,
    "setInterval": 0.7,
    "dangerouslySetInnerHTML": 0.8,
    "setAttribute": 0.6,
    "scriptSrc": 0.7,
    "locationAssignment": 0.6,
    "locationHref": 0.6,
    "domParser": 0.6,
    "jsonParse": 0.5,
    "templateLiteralHtml": 0.7,
    "htmlFromConcatenation": 0.7,
    "innerText": 0.4
  };
  
  // Start with the base confidence for this vulnerability type
  let confidence = baseConfidence[vulnType] || 0.5;
  
  // Extract a context around the match
  const contextStart = Math.max(0, match.index - 200);
  const contextEnd = Math.min(code.length, match.index + match[0].length + 200);
  const context = code.substring(contextStart, contextEnd);
  
  // Increase confidence if there's evidence of user input
  if (/user|input|value|param|request|fetch|get|post|query/.test(context)) {
    confidence += 0.1;
  }
  
  // Decrease confidence if there appears to be sanitization
  if (/sanitize|escape|encodeURI|encodeURIComponent|DOMPurify|filter|validate|purify/.test(context)) {
    confidence -= 0.2;
  }
  
  // Decrease confidence for very small matches that might be false positives
  if (match[0].length < 5) {
    confidence -= 0.1;
  }
  
  // Check for commented-out code which would be a false positive
  if (isMostLikelyComment(code, match.index)) {
    confidence -= 0.5;
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
