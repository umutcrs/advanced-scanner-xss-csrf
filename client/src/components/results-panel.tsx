import { ScanResult, Vulnerability } from "@shared/schema";
import VulnerabilityCard from "./vulnerability-card";
import { useState, useEffect } from "react";
import { AlertCircle, AlertTriangle, Info, Shield, Download, Filter, FileJson, Search, RefreshCw } from "lucide-react";

interface ResultsPanelProps {
  results: ScanResult | null;
  isScanning: boolean;
  originalCode: string;
}

export default function ResultsPanel({ results, isScanning, originalCode }: ResultsPanelProps) {
  const [selectedVulnerability, setSelectedVulnerability] = useState<string | null>(null);
  const [filterSeverity, setFilterSeverity] = useState<string | null>(null);
  const [filterType, setFilterType] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState<string>("");
  const [showFilters, setShowFilters] = useState<boolean>(false);
  
  // Reset selection and filters when new results come in
  useEffect(() => {
    if (results) {
      setSelectedVulnerability(null);
      setFilterSeverity(null);
      setFilterType(null);
      setSearchTerm("");
    }
  }, [results]);
  
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

  // Get severity icon
  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical': return <AlertCircle className="h-4 w-4" />;
      case 'high': return <AlertTriangle className="h-4 w-4" />;
      case 'medium': return <AlertTriangle className="h-4 w-4" />;
      case 'low': return <Info className="h-4 w-4" />;
      default: return <Shield className="h-4 w-4" />;
    }
  };
  
  // Filter vulnerabilities based on selected filters
  const filteredVulnerabilities = results?.vulnerabilities.filter(vuln => {
    // Apply severity filter
    if (filterSeverity && vuln.severity !== filterSeverity) {
      return false;
    }
    
    // Apply type filter
    if (filterType && vuln.type !== filterType) {
      return false;
    }
    
    // Apply search term
    if (searchTerm) {
      const searchLower = searchTerm.toLowerCase();
      return (
        vuln.title.toLowerCase().includes(searchLower) ||
        vuln.description.toLowerCase().includes(searchLower) ||
        vuln.type.toLowerCase().includes(searchLower) ||
        vuln.code.toLowerCase().includes(searchLower)
      );
    }
    
    return true;
  });
  
  // Generate a list of unique vulnerability types for filter dropdown
  const uniqueTypes = results?.vulnerabilities 
    ? [...new Set(results.vulnerabilities.map(v => v.type))]
    : [];
    
  // Export results as JSON
  const exportResults = () => {
    if (!results) return;
    
    const dataStr = JSON.stringify(results, null, 2);
    const dataUri = `data:application/json;charset=utf-8,${encodeURIComponent(dataStr)}`;
    
    const exportFileDefaultName = `security-scan-${new Date().toISOString().slice(0, 10)}.json`;
    
    const linkElement = document.createElement('a');
    linkElement.setAttribute('href', dataUri);
    linkElement.setAttribute('download', exportFileDefaultName);
    linkElement.click();
  };

  return (
    <div className="lg:col-span-2 bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden transition-all duration-300 hover:shadow-md">
      <div className="p-4 border-b border-gray-200 bg-gray-50 flex justify-between items-center">
        <h3 className="text-lg font-medium text-gray-900">Scan Results</h3>
        <div className="flex items-center space-x-2">
          {results && results.vulnerabilities.length > 0 && (
            <button 
              onClick={exportResults}
              className="text-xs text-gray-500 hover:text-gray-700 flex items-center p-1.5 rounded hover:bg-gray-200 transition-colors duration-200"
              title="Export Results"
            >
              <Download className="h-4 w-4" />
            </button>
          )}
          {results && results.vulnerabilities.length > 0 && (
            <button 
              onClick={() => setShowFilters(!showFilters)}
              className={`text-xs ${showFilters ? 'text-blue-600 bg-blue-100' : 'text-gray-500 hover:text-gray-700'} flex items-center p-1.5 rounded hover:bg-gray-200 transition-colors duration-200`}
              title="Filter Results"
            >
              <Filter className="h-4 w-4" />
            </button>
          )}
          <div id="result-status" className={`px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusBadgeStyles()}`}>
            {getStatusBadgeText()}
          </div>
        </div>
      </div>
      
      {/* Filter controls */}
      {showFilters && results && results.vulnerabilities.length > 0 && (
        <div className="p-3 bg-gray-50 border-b border-gray-200 animate-fadeIn">
          <div className="flex flex-wrap gap-2 items-center">
            <div className="flex-1 min-w-[200px]">
              <div className="relative">
                <Search className="absolute left-2 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                <input 
                  type="text" 
                  placeholder="Search vulnerabilities..." 
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full pl-8 pr-4 py-1.5 text-sm border border-gray-300 rounded focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors duration-200"
                />
              </div>
            </div>
            
            <div>
              <select 
                value={filterSeverity || ''} 
                onChange={(e) => setFilterSeverity(e.target.value || null)}
                className="py-1.5 pl-3 pr-8 text-sm border border-gray-300 rounded focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors duration-200"
              >
                <option value="">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
            
            <div>
              <select 
                value={filterType || ''} 
                onChange={(e) => setFilterType(e.target.value || null)}
                className="py-1.5 pl-3 pr-8 text-sm border border-gray-300 rounded focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors duration-200"
              >
                <option value="">All Types</option>
                {uniqueTypes.map(type => (
                  <option key={type} value={type}>{type}</option>
                ))}
              </select>
            </div>
            
            <button 
              onClick={() => {
                setFilterSeverity(null);
                setFilterType(null);
                setSearchTerm("");
              }}
              className="inline-flex items-center px-2 py-1.5 text-sm text-gray-600 hover:text-blue-600 hover:bg-blue-50 rounded transition-colors duration-200"
              title="Reset Filters"
            >
              <RefreshCw className="h-3.5 w-3.5 mr-1" />
              <span>Reset</span>
            </button>
          </div>
        </div>
      )}

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
              <div className="bg-red-50 p-3 rounded-lg hover:shadow-md transition-shadow duration-300 cursor-pointer" 
                   onClick={() => setFilterSeverity(filterSeverity === 'critical' ? null : 'critical')}>
                <div className="text-critical text-2xl font-bold">{results.summary.critical}</div>
                <div className="text-sm text-gray-700 flex items-center">
                  <AlertCircle className="h-3.5 w-3.5 mr-1 text-red-500" />
                  Critical
                </div>
              </div>
              <div className="bg-orange-50 p-3 rounded-lg hover:shadow-md transition-shadow duration-300 cursor-pointer"
                   onClick={() => setFilterSeverity(filterSeverity === 'high' ? null : 'high')}>
                <div className="text-high text-2xl font-bold">{results.summary.high}</div>
                <div className="text-sm text-gray-700 flex items-center">
                  <AlertTriangle className="h-3.5 w-3.5 mr-1 text-orange-500" />
                  High
                </div>
              </div>
              <div className="bg-yellow-50 p-3 rounded-lg hover:shadow-md transition-shadow duration-300 cursor-pointer"
                   onClick={() => setFilterSeverity(filterSeverity === 'medium' ? null : 'medium')}>
                <div className="text-medium text-2xl font-bold">{results.summary.medium}</div>
                <div className="text-sm text-gray-700 flex items-center">
                  <AlertTriangle className="h-3.5 w-3.5 mr-1 text-yellow-500" />
                  Medium
                </div>
              </div>
              <div className="bg-blue-50 p-3 rounded-lg hover:shadow-md transition-shadow duration-300 cursor-pointer"
                   onClick={() => setFilterSeverity(filterSeverity === 'low' ? null : 'low')}>
                <div className="text-blue-500 text-2xl font-bold">{results.summary.low}</div>
                <div className="text-sm text-gray-700 flex items-center">
                  <Info className="h-3.5 w-3.5 mr-1 text-blue-500" />
                  Low
                </div>
              </div>
              <div className="bg-green-50 p-3 rounded-lg hover:shadow-md transition-shadow duration-300">
                <div className="text-success text-2xl font-bold">{results.summary.passedChecks}</div>
                <div className="text-sm text-gray-700 flex items-center">
                  <Shield className="h-3.5 w-3.5 mr-1 text-green-500" />
                  Passed Checks
                </div>
              </div>
            </div>
          </div>

          {/* Vulnerability Details */}
          {results.vulnerabilities.length > 0 ? (
            <div className="p-4">
              <div className="flex justify-between items-center mb-3">
                <h4 className="text-base font-medium text-gray-900">
                  {filteredVulnerabilities && filteredVulnerabilities.length === results.vulnerabilities.length
                    ? "Vulnerability Details"
                    : `Filtered Results (${filteredVulnerabilities?.length || 0} of ${results.vulnerabilities.length})`}
                </h4>
              </div>
              
              <div className="space-y-4">
                {/* Display filtered vulnerabilities or show a message when none match */}
                {filteredVulnerabilities && filteredVulnerabilities.length > 0 ? (
                  filteredVulnerabilities
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
                      <div 
                        key={vulnerability.id} 
                        id={`vuln-${vulnerability.type}`}
                        onClick={() => setSelectedVulnerability(vulnerability.id)}
                      >
                        <VulnerabilityCard 
                          vulnerability={vulnerability} 
                          originalCode={originalCode}
                          isSelected={selectedVulnerability === vulnerability.id}
                        />
                      </div>
                    ))
                ) : (
                  <div className="p-8 text-center bg-gray-50 rounded-lg">
                    <FileJson className="mx-auto h-8 w-8 text-gray-400 mb-2" />
                    <h3 className="text-sm font-medium text-gray-900">No matching vulnerabilities</h3>
                    <p className="mt-1 text-sm text-gray-500">Try adjusting your filters to see more results.</p>
                    <button 
                      onClick={() => {
                        setFilterSeverity(null);
                        setFilterType(null);
                        setSearchTerm("");
                      }}
                      className="mt-3 inline-flex items-center px-3 py-1.5 text-sm text-blue-600 bg-blue-50 hover:bg-blue-100 rounded-full transition-colors duration-200"
                    >
                      <RefreshCw className="h-3.5 w-3.5 mr-1" />
                      <span>Reset Filters</span>
                    </button>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="p-12 text-center">
              <Shield className="mx-auto h-12 w-12 text-green-500" />
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
