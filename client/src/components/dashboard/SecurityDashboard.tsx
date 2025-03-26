import React, { useState } from 'react';
import { ScanResult, Vulnerability } from '@shared/schema';
import ThreatVisualization from './ThreatVisualization';
import ThreatMap from './ThreatMap';
import VulnerabilityTrends from './VulnerabilityTrends';
import { motion } from 'framer-motion';
import { Shield, ShieldAlert, Activity, AlertTriangle, AlertCircle, BarChart4, LineChart, PieChart } from 'lucide-react';

interface SecurityDashboardProps {
  scanResult: ScanResult | null;
  onVulnerabilitySelect?: (vuln: Vulnerability) => void;
}

const SecurityDashboard: React.FC<SecurityDashboardProps> = ({ 
  scanResult, 
  onVulnerabilitySelect 
}) => {
  const [activeTab, setActiveTab] = useState<'visualization' | 'threatMap'>('visualization');
  
  if (!scanResult) {
    return (
      <div className="bg-gray-50 rounded-lg p-6 shadow-sm border flex justify-center items-center h-64">
        <p className="text-gray-500">Run a security scan to see results</p>
      </div>
    );
  }
  
  const hasVulnerabilities = scanResult.vulnerabilities.length > 0;
  
  const getSeverityClassName = () => {
    if (scanResult.summary.critical > 0) return 'text-red-500';
    if (scanResult.summary.high > 0) return 'text-orange-500';
    if (scanResult.summary.medium > 0) return 'text-yellow-500';
    if (scanResult.summary.low > 0) return 'text-blue-500';
    return 'text-green-500';
  };
  
  const getSeverityIcon = () => {
    if (scanResult.summary.critical > 0) return <AlertCircle className="h-6 w-6" />;
    if (scanResult.summary.high > 0) return <ShieldAlert className="h-6 w-6" />;
    if (scanResult.summary.medium > 0) return <AlertTriangle className="h-6 w-6" />;
    if (scanResult.summary.low > 0) return <Activity className="h-6 w-6" />;
    return <Shield className="h-6 w-6" />;
  };
  
  const getSeverityText = () => {
    if (scanResult.summary.critical > 0) return 'Critical vulnerabilities detected';
    if (scanResult.summary.high > 0) return 'High risk issues found';
    if (scanResult.summary.medium > 0) return 'Medium severity issues found';
    if (scanResult.summary.low > 0) return 'Low risk issues found';
    return 'Code is secure';
  };
  
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
      className="bg-white rounded-lg border shadow-sm overflow-hidden"
    >
      <div className="p-4 border-b bg-gray-50">
        <div className="flex justify-between items-center">
          <div className="flex items-center">
            <span className={`mr-2 ${getSeverityClassName()}`}>
              {getSeverityIcon()}
            </span>
            <h2 className="text-xl font-semibold">Security Scan Results</h2>
          </div>
          
          <div className={`px-3 py-1 rounded-full text-sm font-medium ${
            hasVulnerabilities 
              ? 'bg-red-100 text-red-800' 
              : 'bg-green-100 text-green-800'
          }`}>
            {hasVulnerabilities 
              ? `${scanResult.vulnerabilities.length} vulnerabilities` 
              : 'Secure'
            }
          </div>
        </div>
        
        <p className="mt-1 text-sm text-gray-600">
          {getSeverityText()}
        </p>
      </div>
      
      <div className="border-b">
        <div className="flex">
          <button
            className={`px-4 py-2 text-sm font-medium border-b-2 ${
              activeTab === 'visualization'
                ? 'border-blue-500 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
            onClick={() => setActiveTab('visualization')}
          >
            <div className="flex items-center">
              <PieChart className="h-4 w-4 mr-1.5" />
              <span>Visualization</span>
            </div>
          </button>
          
          <button
            className={`px-4 py-2 text-sm font-medium border-b-2 ${
              activeTab === 'threatMap'
                ? 'border-blue-500 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
            onClick={() => setActiveTab('threatMap')}
          >
            <div className="flex items-center">
              <Activity className="h-4 w-4 mr-1.5" />
              <span>Threat Map</span>
            </div>
          </button>
        </div>
      </div>
      
      <div className="p-6">
        {activeTab === 'visualization' ? (
          <ThreatVisualization scanResult={scanResult} />
        ) : (
          <ThreatMap 
            scanResult={scanResult} 
            onVulnerabilitySelect={onVulnerabilitySelect} 
          />
        )}
        
        <div className="mt-2 pt-2 border-t border-gray-100 text-center text-xs text-gray-500">
          Scan completed at {new Date(scanResult.scannedAt).toLocaleString()}
        </div>
      </div>
    </motion.div>
  );
};

export default SecurityDashboard;