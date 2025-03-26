import React, { useState, useEffect } from 'react';
import { ScanResult } from '@shared/schema';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts';
import { motion } from 'framer-motion';
import { AlertCircle, AlertTriangle, Info, Shield } from "lucide-react";

interface ThreatVisualizationProps {
  scanResult: ScanResult | null;
}

interface SeverityData {
  name: string;
  value: number;
  color: string;
  icon: JSX.Element;
}

const ThreatVisualization: React.FC<ThreatVisualizationProps> = ({ scanResult }) => {
  const [chartData, setChartData] = useState<SeverityData[]>([]);
  const [animateChart, setAnimateChart] = useState(false);

  const SEVERITY_COLORS = {
    critical: '#ef4444', // Red
    high: '#f97316',     // Orange
    medium: '#eab308',   // Yellow
    low: '#3b82f6',      // Blue
    info: '#a3a3a3',     // Gray
    passed: '#22c55e',   // Green
  };

  const SEVERITY_ICONS = {
    critical: <AlertCircle className="h-4 w-4" />,
    high: <AlertTriangle className="h-4 w-4" />,
    medium: <AlertTriangle className="h-4 w-4" />,
    low: <Info className="h-4 w-4" />,
    info: <Info className="h-4 w-4" />,
    passed: <Shield className="h-4 w-4" />,
  };

  useEffect(() => {
    if (scanResult) {
      const newData: SeverityData[] = [
        { 
          name: 'Critical', 
          value: scanResult.summary.critical, 
          color: SEVERITY_COLORS.critical,
          icon: SEVERITY_ICONS.critical
        },
        { 
          name: 'High', 
          value: scanResult.summary.high, 
          color: SEVERITY_COLORS.high,
          icon: SEVERITY_ICONS.high
        },
        { 
          name: 'Medium', 
          value: scanResult.summary.medium, 
          color: SEVERITY_COLORS.medium,
          icon: SEVERITY_ICONS.medium
        },
        { 
          name: 'Low', 
          value: scanResult.summary.low, 
          color: SEVERITY_COLORS.low,
          icon: SEVERITY_ICONS.low
        },
        { 
          name: 'Passed', 
          value: scanResult.summary.passedChecks, 
          color: SEVERITY_COLORS.passed,
          icon: SEVERITY_ICONS.passed
        },
      ];
      
      // Filter out zero values for better visualization
      const filteredData = newData.filter(item => item.value > 0);
      setChartData(filteredData);
      setAnimateChart(true);
    }
  }, [scanResult]);

  const CustomTooltip = ({ active, payload }: any) => {
    if (active && payload && payload.length) {
      const data = payload[0].payload;
      return (
        <div className="bg-white p-3 shadow-md rounded border">
          <div className="flex items-center gap-2 font-medium">
            <span style={{ color: data.color }}>{data.icon}</span>
            <span>{data.name}</span>
          </div>
          <p className="text-sm text-gray-700">
            <span className="font-bold">{data.value}</span> {data.name === 'Passed' ? 'checks passed' : 'vulnerabilities found'}
          </p>
        </div>
      );
    }
    return null;
  };

  const renderCustomizedLabel = ({ cx, cy, midAngle, innerRadius, outerRadius, percent, index, name, value }: any) => {
    const RADIAN = Math.PI / 180;
    const radius = innerRadius + (outerRadius - innerRadius) * 0.5;
    const x = cx + radius * Math.cos(-midAngle * RADIAN);
    const y = cy + radius * Math.sin(-midAngle * RADIAN);

    return value > 0 ? (
      <text 
        x={x} 
        y={y} 
        fill="white" 
        textAnchor="middle" 
        dominantBaseline="central"
        className="font-medium"
      >
        {value}
      </text>
    ) : null;
  };

  if (!scanResult) {
    return (
      <div className="bg-gray-50 rounded-lg p-6 shadow-sm border flex justify-center items-center h-64">
        <p className="text-gray-500">No scan results available</p>
      </div>
    );
  }

  const hasVulnerabilities = scanResult.summary.critical > 0 || 
                          scanResult.summary.high > 0 || 
                          scanResult.summary.medium > 0 || 
                          scanResult.summary.low > 0;

  const totalVulnerabilities = scanResult.summary.critical + 
                            scanResult.summary.high + 
                            scanResult.summary.medium + 
                            scanResult.summary.low;

  const securityScore = hasVulnerabilities 
    ? Math.max(0, 100 - (scanResult.summary.critical * 25) - (scanResult.summary.high * 10) - (scanResult.summary.medium * 5) - (scanResult.summary.low * 1))
    : 100;

  const getScoreColor = (score: number) => {
    if (score >= 90) return 'text-green-500';
    if (score >= 70) return 'text-yellow-500';
    if (score >= 40) return 'text-orange-500';
    return 'text-red-500';
  };

  const scoreColor = getScoreColor(securityScore);

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
      <motion.div 
        className="bg-white p-6 rounded-lg shadow-sm border col-span-2"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        <h3 className="text-lg font-semibold mb-4">Threat Distribution</h3>
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={chartData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={renderCustomizedLabel}
                outerRadius={80}
                fill="#8884d8"
                dataKey="value"
                animationDuration={1000}
                animationBegin={animateChart ? 0 : 2000}
              >
                {chartData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip content={<CustomTooltip />} />
              <Legend 
                layout="horizontal" 
                verticalAlign="bottom" 
                align="center"
                formatter={(value, entry: any) => {
                  // Type assertion to avoid TypeScript error
                  const item = entry.payload as SeverityData;
                  return <span style={{ color: item.color }}>{value}</span>;
                }}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </motion.div>

      <motion.div 
        className="bg-white p-6 rounded-lg shadow-sm border h-full"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, delay: 0.2 }}
      >
        <h3 className="text-lg font-semibold mb-4">Security Score</h3>
        <div className="flex flex-col items-center justify-center h-[calc(100%-2rem)]">
          <motion.div 
            className={`text-6xl font-bold ${scoreColor}`}
            initial={{ scale: 0.5 }}
            animate={{ scale: 1 }}
            transition={{ 
              type: "spring", 
              stiffness: 260, 
              damping: 20, 
              delay: 0.5 
            }}
          >
            {securityScore}
          </motion.div>
          <motion.div
            className="text-xl text-gray-500 mt-2 mb-6"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.7 }}
          >
            out of 100
          </motion.div>

          <div className="w-full">
            <div className="flex justify-between text-sm text-gray-600 mb-1">
              <span>Security Status:</span>
              <span className={`font-medium ${scoreColor}`}>
                {securityScore >= 90 ? 'Excellent' : 
                 securityScore >= 70 ? 'Good' : 
                 securityScore >= 40 ? 'Fair' : 'Poor'}
              </span>
            </div>
            
            <div className="text-sm mt-4">
              <div className="flex justify-between mb-1">
                <span className="text-gray-600">Total Vulnerabilities:</span>
                <span className="font-medium">{totalVulnerabilities}</span>
              </div>
              <div className="flex justify-between mb-1">
                <span className="text-gray-600">Checks Passed:</span>
                <span className="font-medium text-green-500">{scanResult.summary.passedChecks}</span>
              </div>
              <div className="flex justify-between mb-1">
                <span className="text-gray-600">Scan Date:</span>
                <span className="font-medium">{new Date(scanResult.scannedAt).toLocaleString()}</span>
              </div>
            </div>
          </div>
        </div>
      </motion.div>
    </div>
  );
};

export default ThreatVisualization;