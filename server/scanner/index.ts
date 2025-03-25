import { scanPatterns } from "./patterns";
import { ScanResult, Vulnerability } from "@shared/schema";
import { 
  extractCodeSnippet, 
  countPatternMatches, 
  analyzeDataFlow, 
  calculateConfidenceScore,
  formatCodeSnippet
} from "./utils";
import { v4 as uuidv4 } from "uuid";

// Confidence threshold - vulnerabilities with lower scores will be excluded
const CONFIDENCE_THRESHOLD = 0.35; // Lower threshold to catch more potential issues

/**
 * Advanced scanning engine for detecting XSS vulnerabilities in JavaScript code
 * Employs multiple analysis techniques to minimize false positives and provide accurate results
 * 
 * @param code The JavaScript code to scan
 * @returns A scan result object with vulnerabilities and summary
 */
export async function scanJavaScriptCode(code: string): Promise<ScanResult> {
  // Validate and prepare the code for scanning
  const preparedCode = prepareCodeForScanning(code);
  
  // First pass: Collect all potential vulnerability matches
  const potentialVulnerabilities: Array<{
    index: number;
    length: number;
    type: string;
    pattern: typeof scanPatterns[0];
    match: RegExpExecArray;
  }> = [];
  
  // Run all vulnerability patterns against the code
  for (const pattern of scanPatterns) {
    const regex = pattern.regex;
    regex.lastIndex = 0; // Reset regex state
    
    let match;
    while ((match = regex.exec(preparedCode)) !== null) {
      potentialVulnerabilities.push({
        index: match.index,
        length: match[0].length,
        type: pattern.type,
        pattern,
        match
      });
    }
  }
  
  // Second pass: Analyze data flow to reduce false positives
  const validatedIndices = analyzeDataFlow(
    preparedCode, 
    potentialVulnerabilities.map(v => ({ 
      index: v.index, 
      length: v.length, 
      type: v.type 
    }))
  );
  
  // Extract the validated vulnerabilities
  const validatedVulnerabilities = potentialVulnerabilities.filter(v => 
    validatedIndices.some(valid => 
      valid.index === v.index && valid.length === v.length && valid.type === v.type
    )
  );
  
  // Third pass: Calculate confidence scores and filter out low-confidence matches
  const finalVulnerabilities: Vulnerability[] = [];
  
  for (const vul of validatedVulnerabilities) {
    // Get a code snippet for context - we need this for further analysis
    const codeSnippet = extractCodeSnippet(preparedCode, vul.index, vul.length);
    
    // Special case for image src assignments with proper sanitization
    if ((vul.type === 'imageSrcAssignment' || vul.type.includes('Src')) && 
        codeSnippet.includes('document.createTextNode') && 
        codeSnippet.includes('.textContent')) {
      // This is properly sanitized, so skip it regardless of confidence
      continue;
    }
    
    const confidence = calculateConfidenceScore(preparedCode, vul.match, vul.type);
    
    // Only include vulnerabilities that meet our confidence threshold
    if (confidence >= CONFIDENCE_THRESHOLD) {
      
      // Calculate line and column numbers
      const codeUpToMatch = preparedCode.substring(0, vul.index);
      const lines = codeUpToMatch.split('\n');
      const lineNumber = lines.length;
      const columnNumber = lines[lines.length - 1]?.length + 1 || 0;
      
      const vulnerability: Vulnerability = {
        id: uuidv4(),
        type: vul.type,
        severity: vul.pattern.severity,
        title: vul.pattern.title,
        description: vul.pattern.description,
        code: codeSnippet,
        line: lineNumber,
        column: columnNumber,
        recommendation: vul.pattern.recommendation,
        recommendationCode: vul.pattern.recommendationCode,
      };
      
      finalVulnerabilities.push(vulnerability);
    }
  }
  
  // Deduplicate vulnerabilities that refer to the same code snippet
  const uniqueVulnerabilities = deduplicateVulnerabilities(finalVulnerabilities);
  
  // Enrich vulnerability data with additional context if needed
  const enrichedVulnerabilities = uniqueVulnerabilities.map(vuln => {
    // Format code snippets more nicely
    vuln.code = formatCodeSnippet(vuln.code);
    
    // Add additional context to recommendations for specific vulnerability types
    if (vuln.type === "eval" || vuln.type === "Function" || vuln.type === "setTimeout" || vuln.type === "setInterval") {
      vuln.description += " This is one of the most serious XSS vulnerabilities as it allows direct code execution.";
    }
    
    if (vuln.type.includes("HTML") || vuln.type.includes("html")) {
      // Add link to OWASP for HTML-based XSS vulnerabilities
      vuln.description += " See OWASP guidelines for handling HTML content safely.";
    }
    
    return vuln;
  });
  
  // Sort vulnerabilities by severity for better presentation (critical first)
  const sortedVulnerabilities = sortVulnerabilitiesBySeverity(enrichedVulnerabilities);
  
  // Enhanced summary statistics
  const summary = {
    critical: countPatternMatches(sortedVulnerabilities, "critical"),
    high: countPatternMatches(sortedVulnerabilities, "high"),
    medium: countPatternMatches(sortedVulnerabilities, "medium"),
    low: countPatternMatches(sortedVulnerabilities, "low"),
    info: countPatternMatches(sortedVulnerabilities, "info"),
    total: sortedVulnerabilities.length,
    uniqueTypes: new Set(sortedVulnerabilities.map((v: Vulnerability) => v.type)).size,
    passedChecks: scanPatterns.length - new Set(sortedVulnerabilities.map((v: Vulnerability) => v.type)).size
  };
  
  return {
    vulnerabilities: sortedVulnerabilities,
    summary,
    scannedAt: new Date().toISOString()
  };
}

/**
 * Prepares code for scanning by handling edge cases and normalizing whitespace
 * @param code The raw JavaScript code
 * @returns Prepared code for analysis
 */
function prepareCodeForScanning(code: string): string {
  if (!code || typeof code !== 'string') {
    return '';
  }
  
  // Normalize input by removing Byte Order Mark (BOM) if present
  let preparedCode = code.replace(/^\uFEFF/, '');
  
  // Replace minified semicolons with newlines to improve pattern matching
  preparedCode = preparedCode.replace(/;(?=\S)/g, ';\n');
  
  // Add spaces around operators for better pattern matching
  preparedCode = preparedCode
    .replace(/([+\-*/%&|^<>=!])([\w$.])/g, '$1 $2')  // Add space after operator
    .replace(/([\w$.])([+\-*/%&|^<>=!])/g, '$1 $2'); // Add space before operator
  
  // Handle CR/CRLF line endings
  preparedCode = preparedCode.replace(/\r\n?/g, '\n');
  
  // Break up complex statements on same line
  preparedCode = preparedCode.replace(/([;{}])\s*([^\s;{}])/g, '$1\n$2');
  
  // Clean up extra whitespace without changing actual content
  preparedCode = preparedCode
    .replace(/[ \t]+/g, ' ')         // Multiple spaces/tabs to single space
    .replace(/\n[ \t]+/g, '\n')      // Leading whitespace
    .replace(/[ \t]+\n/g, '\n');     // Trailing whitespace
    
  // Ensure function blocks are nicely formatted
  preparedCode = preparedCode.replace(/\)\s*{/g, ') {');
  
  // Make sure pattern matching has enough whitespace to work with
  preparedCode = preparedCode.replace(/([a-zA-Z0-9_$])\(/g, '$1 (');
  
  return preparedCode;
}

/**
 * Removes duplicate vulnerabilities that point to the same issue
 * @param vulnerabilities Array of detected vulnerabilities
 * @returns Deduplicated array of vulnerabilities
 */
function deduplicateVulnerabilities(vulnerabilities: Vulnerability[]): Vulnerability[] {
  // Sort vulnerabilities by severity (critical first) and then by type
  const sortedVulnerabilities = [...vulnerabilities].sort((a, b) => {
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const aSeverity = severityOrder[a.severity as keyof typeof severityOrder] || 5;
    const bSeverity = severityOrder[b.severity as keyof typeof severityOrder] || 5;
    
    if (aSeverity !== bSeverity) {
      return aSeverity - bSeverity;
    }
    
    return a.type.localeCompare(b.type);
  });
  
  const uniqueVulnerabilities: Vulnerability[] = [];
  const seenPatterns = new Set<string>();
  
  for (const vuln of sortedVulnerabilities) {
    // Create a key based on the code snippet and type to identify duplicates
    // We normalize whitespace and use a smaller part of the snippet
    const snippetKey = vuln.code
      .replace(/\s+/g, ' ')
      .substring(0, 100) + ':' + vuln.type;
    
    if (!seenPatterns.has(snippetKey)) {
      seenPatterns.add(snippetKey);
      uniqueVulnerabilities.push(vuln);
    }
  }
  
  return uniqueVulnerabilities;
}

/**
 * Sorts vulnerabilities by severity and line number for better presentation 
 * @param vulnerabilities Array of vulnerabilities to sort
 * @returns Sorted vulnerabilities array
 */
function sortVulnerabilitiesBySeverity(vulnerabilities: Vulnerability[]): Vulnerability[] {
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  
  return [...vulnerabilities].sort((a, b) => {
    // First, sort by severity
    const aSeverity = severityOrder[a.severity as keyof typeof severityOrder] || 5;
    const bSeverity = severityOrder[b.severity as keyof typeof severityOrder] || 5;
    
    if (aSeverity !== bSeverity) {
      return aSeverity - bSeverity;
    }
    
    // Then sort by line number if available
    if (a.line && b.line && a.line !== b.line) {
      return a.line - b.line;
    }
    
    // Finally sort by vulnerability type
    return a.type.localeCompare(b.type);
  });
}
