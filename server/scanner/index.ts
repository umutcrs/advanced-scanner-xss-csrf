import { scanPatterns } from "./patterns";
import { ScanResult, Vulnerability } from "@shared/schema";
import { extractCodeSnippet, countPatternMatches } from "./utils";
import { v4 as uuidv4 } from "uuid";

/**
 * Scans JavaScript code for XSS vulnerabilities
 * @param code The JavaScript code to scan
 * @returns A scan result object with vulnerabilities and summary
 */
export async function scanJavaScriptCode(code: string): Promise<ScanResult> {
  const vulnerabilities: Vulnerability[] = [];
  
  // Run all vulnerability patterns against the code
  for (const pattern of scanPatterns) {
    const regex = pattern.regex;
    regex.lastIndex = 0; // Reset regex state
    
    let match;
    while ((match = regex.exec(code)) !== null) {
      const matchedCode = match[0];
      
      // Get a code snippet for context
      const codeSnippet = extractCodeSnippet(code, match.index, matchedCode.length);
      
      const vulnerability: Vulnerability = {
        id: uuidv4(),
        type: pattern.type,
        severity: pattern.severity,
        title: pattern.title,
        description: pattern.description,
        code: codeSnippet,
        recommendation: pattern.recommendation,
        recommendationCode: pattern.recommendationCode,
      };
      
      vulnerabilities.push(vulnerability);
    }
  }
  
  // Count vulnerabilities by severity
  const summary = {
    critical: countPatternMatches(vulnerabilities, "critical"),
    high: countPatternMatches(vulnerabilities, "high"),
    medium: countPatternMatches(vulnerabilities, "medium"),
    low: countPatternMatches(vulnerabilities, "low"),
    info: countPatternMatches(vulnerabilities, "info"),
    passedChecks: scanPatterns.length - new Set(vulnerabilities.map(v => v.type)).size
  };
  
  return {
    vulnerabilities,
    summary,
    scannedAt: new Date().toISOString()
  };
}
