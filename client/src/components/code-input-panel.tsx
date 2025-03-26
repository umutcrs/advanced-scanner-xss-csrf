import React, { useState, useRef, useEffect } from "react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { useToast } from "@/hooks/use-toast";
import CodeEditor from "@/lib/code-editor";

interface CodeInputPanelProps {
  onScan: (code: string, fileName?: string) => void;
  isScanning: boolean;
  initialCode?: string;
}

const SAMPLE_CODE = `// Example vulnerable code
function displayUserInput() {
  const userInput = document.getElementById('user-input').value;
  document.getElementById('output').innerHTML = userInput;
}

function createLink() {
  const url = document.getElementById('url-input').value;
  const element = document.createElement('a');
  element.setAttribute('href', url);
  element.innerHTML = 'Click me';
  document.body.appendChild(element);
}

function loadScript() {
  const scriptUrl = getParameterByName('src');
  const script = document.createElement('script');
  script.src = scriptUrl;
  document.head.appendChild(script);
}

// Potentially vulnerable eval usage
function calculateExpression() {
  const expr = document.getElementById('expression').value;
  const result = eval(expr);
  return result;
}`;

export default function CodeInputPanel({ onScan, isScanning, initialCode }: CodeInputPanelProps) {
  const [code, setCode] = useState(initialCode || SAMPLE_CODE);
  const [fileName, setFileName] = useState<string | undefined>();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const { toast } = useToast();
  
  // Update code when initialCode changes (for code fixes)
  useEffect(() => {
    if (initialCode) {
      setCode(initialCode);
    }
  }, [initialCode]);

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (file.size > 5 * 1024 * 1024) {
      toast({
        title: "File too large",
        description: "Maximum file size is 5MB",
        variant: "destructive",
      });
      return;
    }

    if (!file.name.endsWith('.js')) {
      toast({
        title: "Invalid file type",
        description: "Only JavaScript (.js) files are accepted",
        variant: "destructive",
      });
      return;
    }

    setFileName(file.name);
    
    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result as string;
      setCode(content);
    };
    reader.readAsText(file);
  };

  const handleScan = () => {
    if (!code.trim()) {
      toast({
        title: "No code to scan",
        description: "Please enter or upload some JavaScript code",
        variant: "destructive",
      });
      return;
    }
    onScan(code, fileName);
  };

  return (
    <div className="lg:col-span-1 bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
      <div className="p-4 border-b border-gray-200 bg-gray-50">
        <h3 className="text-lg font-medium text-gray-900">Code Input</h3>
      </div>
      <div className="p-4">
        <Tabs defaultValue="paste">
          <TabsList className="mb-4 border-b border-gray-200 w-full justify-start">
            <TabsTrigger value="paste" className="px-4 py-2 text-sm font-medium data-[state=active]:text-accent data-[state=active]:border-b-2 data-[state=active]:border-accent">
              Paste Code
            </TabsTrigger>
            <TabsTrigger value="upload" className="px-4 py-2 text-sm font-medium data-[state=active]:text-accent data-[state=active]:border-b-2 data-[state=active]:border-accent">
              Upload File
            </TabsTrigger>
          </TabsList>
          
          <TabsContent value="paste" className="space-y-4">
            <div>
              <label htmlFor="code-input" className="block text-sm font-medium text-gray-700 mb-1">
                JavaScript Code
              </label>
              <div className="border rounded-md">
                <CodeEditor 
                  value={code} 
                  onChange={setCode} 
                  language="javascript"
                  height="400px" 
                  maxVisibleLines={150}
                />
              </div>
            </div>
          </TabsContent>
          
          <TabsContent value="upload" className="space-y-4">
            <div className="border-2 border-dashed border-gray-300 rounded-md px-6 pt-5 pb-6 flex justify-center">
              <div className="space-y-1 text-center">
                <svg className="mx-auto h-12 w-12 text-gray-400" stroke="currentColor" fill="none" viewBox="0 0 48 48">
                  <path d="M28 8H12a4 4 0 00-4 4v20m32-12v8m0 0v8a4 4 0 01-4 4H12a4 4 0 01-4-4v-4m32-4l-3.172-3.172a4 4 0 00-5.656 0L28 28M8 32l9.172-9.172a4 4 0 015.656 0L28 28m0 0l4 4m4-24h8m-4-4v8m-12 4h.02" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"></path>
                </svg>
                <div className="flex text-sm text-gray-600">
                  <label htmlFor="file-upload" className="relative cursor-pointer bg-white rounded-md font-medium text-accent hover:text-accent focus-within:outline-none">
                    <span>Upload a file</span>
                    <input 
                      id="file-upload" 
                      name="file-upload" 
                      type="file" 
                      className="sr-only"
                      ref={fileInputRef}
                      onChange={handleFileUpload}
                      accept=".js"
                    />
                  </label>
                  <p className="pl-1">or drag and drop</p>
                </div>
                <p className="text-xs text-gray-500">.js files up to 5MB</p>
              </div>
            </div>
            {fileName && (
              <div className="text-sm font-medium text-gray-700">
                Selected file: {fileName}
              </div>
            )}
          </TabsContent>
        </Tabs>

        <div className="mt-6">
          <Button 
            className="w-full bg-accent hover:bg-opacity-90" 
            onClick={handleScan}
            disabled={isScanning}
          >
            {isScanning ? (
              <>
                <div className="inline-block animate-spin rounded-full h-4 w-4 border-t-2 border-b-2 border-white mr-2"></div>
                Scanning...
              </>
            ) : (
              <>
                <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-2" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M6.672 1.911a1 1 0 10-1.932.518l.259.966a1 1 0 001.932-.518l-.26-.966zM2.429 4.74a1 1 0 10-.517 1.932l.966.259a1 1 0 00.517-1.932l-.966-.26zm8.814-.569a1 1 0 00-1.415-1.414l-.707.707a1 1 0 101.415 1.415l.707-.708zm-7.071 7.072l.707-.707A1 1 0 003.465 9.12l-.708.707a1 1 0 001.415 1.415zm3.2-5.171a1 1 0 00-1.3 1.3l4 10a1 1 0 001.823.075l1.38-2.759 3.018 3.02a1 1 0 001.414-1.415l-3.019-3.02 2.76-1.379a1 1 0 00-.076-1.822l-10-4z" clipRule="evenodd" />
                </svg>
                Scan for XSS Vulnerabilities
              </>
            )}
          </Button>
        </div>
      </div>
    </div>
  );
}
