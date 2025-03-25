import { Vulnerability } from "@shared/schema";

/**
 * Extracts a code snippet from the source code, providing context around the vulnerability
 * @param code The full source code
 * @param index The starting index of the vulnerability
 * @param length The length of the vulnerable code
 * @returns A formatted code snippet with context
 */
export function extractCodeSnippet(code: string, index: number, length: number): string {
  // Get a bit of context around the vulnerability (up to 50 chars before and 100 after)
  const startIndex = Math.max(0, index - 50);
  const endIndex = Math.min(code.length, index + length + 100);
  
  // Extract the code snippet with context
  let codeSnippet = code.substring(startIndex, endIndex);
  
  // If we truncated the beginning, add ellipsis
  if (startIndex > 0) {
    codeSnippet = "..." + codeSnippet;
  }
  
  // If we truncated the end, add ellipsis
  if (endIndex < code.length) {
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
