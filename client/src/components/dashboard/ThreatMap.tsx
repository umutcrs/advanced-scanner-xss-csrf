import React, { useMemo } from 'react';
import { ScanResult, Vulnerability } from '@shared/schema';
import { motion } from 'framer-motion';
import { Shield, ShieldAlert, ShieldOff, AlertTriangle, AlertCircle, Info } from 'lucide-react';

interface ThreatMapProps {
  scanResult: ScanResult | null;
  onVulnerabilitySelect?: (vuln: Vulnerability) => void;
}

const ThreatMap: React.FC<ThreatMapProps> = ({ scanResult, onVulnerabilitySelect }) => {
  // Group vulnerabilities by type for better visualization
  const groupedVulnerabilities = useMemo(() => {
    if (!scanResult || !scanResult.vulnerabilities.length) return {};
    
    return scanResult.vulnerabilities.reduce((acc, vuln) => {
      if (!acc[vuln.type]) {
        acc[vuln.type] = [];
      }
      acc[vuln.type].push(vuln);
      return acc;
    }, {} as Record<string, Vulnerability[]>);
  }, [scanResult]);

  // Get vulnerability types with count
  const vulnerabilityTypes = useMemo(() => {
    if (!scanResult) return [];
    
    return Object.entries(groupedVulnerabilities).map(([type, vulns]) => ({
      type,
      count: vulns.length,
      severity: vulns[0].severity, // Use the severity of the first vulnerability in the group
    }));
  }, [scanResult, groupedVulnerabilities]);

  // Get severity icon
  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical': return <ShieldOff className="h-5 w-5" />;
      case 'high': return <ShieldAlert className="h-5 w-5" />;
      case 'medium': return <AlertTriangle className="h-5 w-5" />;
      case 'low': return <Info className="h-5 w-5" />;
      default: return <Shield className="h-5 w-5" />;
    }
  };

  // Get severity color
  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'rgb(239, 68, 68)';
      case 'high': return 'rgb(249, 115, 22)';
      case 'medium': return 'rgb(234, 179, 8)';
      case 'low': return 'rgb(59, 130, 246)';
      default: return 'rgb(163, 163, 163)';
    }
  };

  // Get background color based on severity for the threat node
  const getNodeBgColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-100';
      case 'high': return 'bg-orange-100';
      case 'medium': return 'bg-yellow-100';
      case 'low': return 'bg-blue-100';
      default: return 'bg-gray-100';
    }
  };

  // Format vulnerability type name for display
  const formatVulnType = (type: string) => {
    // Convert camelCase to words with spaces
    return type
      .replace(/([A-Z])/g, ' $1')
      .replace(/^./, (str) => str.toUpperCase())
      .trim();
  };

  if (!scanResult) {
    return (
      <div className="bg-gray-50 rounded-lg p-6 shadow-sm border flex justify-center items-center h-64">
        <p className="text-gray-500">No scan results available</p>
      </div>
    );
  }

  if (!scanResult.vulnerabilities.length) {
    return (
      <div className="bg-gray-50 rounded-lg p-6 shadow-sm border flex flex-col justify-center items-center h-64">
        <Shield className="h-16 w-16 text-green-500 mb-4" />
        <p className="text-gray-700 font-medium">No vulnerabilities detected</p>
        <p className="text-gray-500 text-sm">{scanResult.summary.passedChecks} security checks passed</p>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-lg shadow-sm border p-6 mb-6">
      <h3 className="text-lg font-semibold mb-4">Interactive Threat Map</h3>
      
      <div className="flex flex-wrap gap-2 mb-4">
        {['critical', 'high', 'medium', 'low'].map(severity => (
          <div key={severity} className="flex items-center text-xs">
            <div className="w-3 h-3 rounded-full mr-1" style={{ backgroundColor: getSeverityColor(severity) }}></div>
            <span className="capitalize">{severity}</span>
          </div>
        ))}
      </div>
      
      <div className="p-4">
        <div className="relative">
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="w-20 h-20 rounded-full bg-gray-100 flex items-center justify-center">
              <AlertCircle className="h-10 w-10 text-gray-400" />
            </div>
          </div>
          
          <div className="flex flex-wrap justify-center gap-6 py-10">
            {vulnerabilityTypes.map((vulnType, index) => (
              <motion.div
                key={vulnType.type}
                className={`${getNodeBgColor(vulnType.severity)} p-3 rounded-lg shadow cursor-pointer transition-transform border border-gray-200 hover:scale-105`}
                initial={{ opacity: 0, scale: 0.8 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ 
                  duration: 0.5,
                  delay: index * 0.1,
                  type: "spring",
                  stiffness: 100
                }}
                onClick={() => {
                  if (onVulnerabilitySelect && groupedVulnerabilities[vulnType.type][0]) {
                    onVulnerabilitySelect(groupedVulnerabilities[vulnType.type][0]);
                  }
                }}
                whileHover={{ 
                  scale: 1.05,
                  transition: { duration: 0.2 }
                }}
              >
                <div className="flex items-center mb-2">
                  <div style={{ color: getSeverityColor(vulnType.severity) }} className="mr-2">
                    {getSeverityIcon(vulnType.severity)}
                  </div>
                  <div className="font-medium text-sm">
                    {formatVulnType(vulnType.type)}
                  </div>
                </div>
                
                <div className="border-t pt-2 mt-1">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-gray-600">Instances:</span>
                    <span className="font-medium text-sm">{vulnType.count}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-gray-600">Severity:</span>
                    <span className="font-medium text-sm capitalize">{vulnType.severity}</span>
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </div>
      
      <div className="text-sm text-gray-500 text-center mt-2">
        Click on a vulnerability type to see details
      </div>
    </div>
  );
};

export default ThreatMap;