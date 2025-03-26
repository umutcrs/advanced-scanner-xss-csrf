import { useState, useRef } from "react";
import CodeInputPanel from "@/components/code-input-panel";
import ResultsPanel from "@/components/results-panel";
import { SecurityDashboard } from "@/components/dashboard";
import { ScanResult, Vulnerability } from "@shared/schema";
import { useMutation } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { motion } from "framer-motion";

export default function Home() {
  const [scanResults, setScanResults] = useState<ScanResult | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [currentCode, setCurrentCode] = useState<string>("");
  const { toast } = useToast();

  const scanMutation = useMutation({
    mutationFn: async (code: { code: string; fileName?: string }) => {
      const response = await apiRequest('POST', '/api/scan', code);
      return response.json();
    },
    onSuccess: (data: ScanResult) => {
      setScanResults(data);
      setIsScanning(false);
    },
    onError: (error) => {
      toast({
        title: "Scan failed",
        description: error.message || "Something went wrong during the scan",
        variant: "destructive",
      });
      setIsScanning(false);
    }
  });

  const handleScan = async (code: string, fileName?: string) => {
    setIsScanning(true);
    setCurrentCode(code);
    scanMutation.mutate({ code, fileName });
  };
  


  const [selectedVulnerability, setSelectedVulnerability] = useState<Vulnerability | null>(null);
  const resultsRef = useRef<HTMLDivElement>(null);

  // Handle clicking on a vulnerability in the threat map
  const handleVulnerabilitySelect = (vuln: Vulnerability) => {
    setSelectedVulnerability(vuln);
    
    // Scroll to results panel
    setTimeout(() => {
      if (resultsRef.current) {
        resultsRef.current.scrollIntoView({ behavior: 'smooth' });
      }
    }, 100);
  };

  return (
    <div className="min-h-screen flex flex-col bg-gray-50">
      <header className="bg-white border-b border-gray-200 shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center">
              <svg xmlns="http://www.w3.org/2000/svg" className="h-8 w-8 text-accent" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M12.316 3.051a1 1 0 01.633 1.265l-4 12a1 1 0 11-1.898-.632l4-12a1 1 0 011.265-.633zM5.707 6.293a1 1 0 010 1.414L3.414 10l2.293 2.293a1 1 0 11-1.414 1.414l-3-3a1 1 0 010-1.414l3-3a1 1 0 011.414 0zm8.586 0a1 1 0 011.414 0l3 3a1 1 0 010 1.414l-3 3a1 1 0 11-1.414-1.414L16.586 10l-2.293-2.293a1 1 0 010-1.414z" clipRule="evenodd" />
              </svg>
              <h1 className="ml-2 text-xl font-semibold">JavaScript XSS Scanner</h1>
            </div>
            <div className="flex items-center">
              <a href="https://github.com/owasp/xss-prevention-cheat-sheet" target="_blank" rel="noopener noreferrer" className="text-gray-500 hover:text-accent px-3 py-2 text-sm font-medium">Documentation</a>
              <a href="https://owasp.org/www-community/attacks/xss/" target="_blank" rel="noopener noreferrer" className="text-gray-500 hover:text-accent px-3 py-2 text-sm font-medium">About XSS</a>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 flex-grow">
        <div className="mb-8">
          <h2 className="text-2xl font-bold text-gray-900 mb-2">XSS Vulnerability Scanner</h2>
          <p className="text-gray-600 max-w-3xl">Analyze your JavaScript code for Cross-Site Scripting (XSS) vulnerabilities. Upload a file or paste your code to identify potential security issues.</p>
        </div>

        {scanResults && (
          <motion.div 
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4 }}
            className="mb-10"
          >
            <SecurityDashboard 
              scanResult={scanResults} 
              onVulnerabilitySelect={handleVulnerabilitySelect}
            />
          </motion.div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <CodeInputPanel 
            onScan={handleScan} 
            isScanning={isScanning} 
            initialCode={currentCode}
          />
          <div className="lg:col-span-2" ref={resultsRef}>
            <ResultsPanel 
              results={scanResults} 
              isScanning={isScanning} 
              originalCode={currentCode}
            />
          </div>
        </div>
      </main>

      <footer className="bg-white border-t border-gray-200">
        <div className="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8">
          <div className="md:flex md:items-center md:justify-between">
            <div className="flex justify-center md:justify-start space-x-6">
              <a href="https://github.com/" className="text-gray-400 hover:text-gray-500">
                <span className="sr-only">GitHub</span>
                <svg className="h-6 w-6" fill="currentColor" viewBox="0 0 24 24">
                  <path fillRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" clipRule="evenodd" />
                </svg>
              </a>
            </div>
            <p className="mt-8 text-center text-base text-gray-400 md:mt-0 md:text-right">
              &copy; {new Date().getFullYear()} JavaScript XSS Scanner. All rights reserved.
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}
