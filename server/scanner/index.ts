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
const CONFIDENCE_THRESHOLD = 0.4;

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
    const confidence = calculateConfidenceScore(preparedCode, vul.match, vul.type);
    
    // Only include vulnerabilities that meet our confidence threshold
    if (confidence >= CONFIDENCE_THRESHOLD) {
      // Get a code snippet for context
      const codeSnippet = extractCodeSnippet(preparedCode, vul.index, vul.length);
      
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
  
  // Count vulnerabilities by severity for summary
  const summary = {
    critical: countPatternMatches(uniqueVulnerabilities, "critical"),
    high: countPatternMatches(uniqueVulnerabilities, "high"),
    medium: countPatternMatches(uniqueVulnerabilities, "medium"),
    low: countPatternMatches(uniqueVulnerabilities, "low"),
    info: countPatternMatches(uniqueVulnerabilities, "info"),
    passedChecks: scanPatterns.length - new Set(uniqueVulnerabilities.map(v => v.type)).size
  };
  
  return {
    vulnerabilities: uniqueVulnerabilities,
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
  
  // Replace minified semicolons with newlines to improve pattern matching
  let preparedCode = code.replace(/;(?=\S)/g, ';\n');
  
  // Handle CR/CRLF line endings
  preparedCode = preparedCode.replace(/\r\n?/g, '\n');
  
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
