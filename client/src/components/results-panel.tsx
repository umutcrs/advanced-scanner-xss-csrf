import { ScanResult } from "@shared/schema";
import VulnerabilityCard from "./vulnerability-card";
import { useState } from "react";

interface ResultsPanelProps {
  results: ScanResult | null;
  isScanning: boolean;
  originalCode: string;
  onCodeFixed: (fixedCode: string) => void;
}

export default function ResultsPanel({ results, isScanning, originalCode, onCodeFixed }: ResultsPanelProps) {
  // Helper function to get the background color based on severity
  const getSeverityBgColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-50';
      case 'high': return 'bg-orange-50';
      case 'medium': return 'bg-yellow-50';
      case 'low': return 'bg-blue-50';
      default: return 'bg-green-50';
    }
  };

  // Helper function to get the text color based on severity
  const getSeverityTextColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-critical';
      case 'high': return 'text-high';
      case 'medium': return 'text-medium';
      case 'low': return 'text-blue-500';
      default: return 'text-success';
    }
  };

  // Status badge styles
  const getStatusBadgeStyles = () => {
    if (isScanning) {
      return 'bg-blue-100 text-blue-800';
    }
    if (!results) {
      return 'bg-gray-200 text-gray-800';
    }
    if (results.vulnerabilities.length === 0) {
      return 'bg-green-100 text-green-800';
    }
    return 'bg-red-100 text-red-800';
  };

  // Status badge text
  const getStatusBadgeText = () => {
    if (isScanning) {
      return 'Scanning...';
    }
    if (!results) {
      return 'Ready to Scan';
    }
    if (results.vulnerabilities.length === 0) {
      return 'No Vulnerabilities';
    }
    return 'Vulnerabilities Found';
  };

  return (
    <div className="lg:col-span-2 bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
      <div className="p-4 border-b border-gray-200 bg-gray-50 flex justify-between items-center">
        <h3 className="text-lg font-medium text-gray-900">Scan Results</h3>
        <div id="result-status" className={`px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusBadgeStyles()}`}>
          {getStatusBadgeText()}
        </div>
      </div>

      {/* Loading state */}
      {isScanning && (
        <div className="p-12 text-center">
          <div className="inline-block animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-accent mb-4"></div>
          <p className="text-gray-600">Scanning for XSS vulnerabilities...</p>
        </div>
      )}

      {/* Results state */}
      {!isScanning && results && (
        <div className="divide-y divide-gray-200">
          {/* Summary Section */}
          <div className="p-4">
            <h4 className="text-base font-medium text-gray-900 mb-3">Summary</h4>
            <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
              <div className="bg-red-50 p-3 rounded-lg">
                <div className="text-critical text-2xl font-bold">{results.summary.critical}</div>
                <div className="text-sm text-gray-700">Critical</div>
              </div>
              <div className="bg-orange-50 p-3 rounded-lg">
                <div className="text-high text-2xl font-bold">{results.summary.high}</div>
                <div className="text-sm text-gray-700">High</div>
              </div>
              <div className="bg-yellow-50 p-3 rounded-lg">
                <div className="text-medium text-2xl font-bold">{results.summary.medium}</div>
                <div className="text-sm text-gray-700">Medium</div>
              </div>
              <div className="bg-blue-50 p-3 rounded-lg">
                <div className="text-blue-500 text-2xl font-bold">{results.summary.low}</div>
                <div className="text-sm text-gray-700">Low</div>
              </div>
              <div className="bg-green-50 p-3 rounded-lg">
                <div className="text-success text-2xl font-bold">{results.summary.passedChecks}</div>
                <div className="text-sm text-gray-700">Passed Checks</div>
              </div>
            </div>
          </div>

          {/* Vulnerability Details */}
          {results.vulnerabilities.length > 0 ? (
            <div className="p-4">
              <h4 className="text-base font-medium text-gray-900 mb-3">Vulnerability Details</h4>
              <div className="space-y-4">
                {/* Sort again by severity to ensure critical vulnerabilities are always at the top */}
                {results.vulnerabilities
                  .sort((a, b) => {
                    const severityOrder: Record<string, number> = {
                      'critical': 0,
                      'high': 1,
                      'medium': 2,
                      'low': 3,
                      'info': 4
                    };
                    return severityOrder[a.severity] - severityOrder[b.severity];
                  })
                  .map((vulnerability) => (
                    <VulnerabilityCard 
                      key={vulnerability.id} 
                      vulnerability={vulnerability} 
                      originalCode={originalCode}
                      onCodeFixed={onCodeFixed}
                    />
                  ))
                }
              </div>
            </div>
          ) : (
            <div className="p-12 text-center">
              <svg xmlns="http://www.w3.org/2000/svg" className="mx-auto h-12 w-12 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
              <h3 className="mt-2 text-sm font-medium text-gray-900">No vulnerabilities found</h3>
              <p className="mt-1 text-sm text-gray-500">Your code looks clean and doesn't contain common XSS vulnerabilities.</p>
            </div>
          )}
        </div>
      )}

      {/* Empty state */}
      {!isScanning && !results && (
        <div className="p-12 text-center">
          <svg xmlns="http://www.w3.org/2000/svg" className="mx-auto h-12 w-12 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
          </svg>
          <h3 className="mt-2 text-sm font-medium text-gray-900">No scan results yet</h3>
          <p className="mt-1 text-sm text-gray-500">Paste or upload JavaScript code and click "Scan" to detect XSS vulnerabilities.</p>
        </div>
      )}
    </div>
  );
}
