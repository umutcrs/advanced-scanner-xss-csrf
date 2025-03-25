import { useState, useEffect, useRef } from "react";

interface CodeEditorProps {
  value: string;
  onChange: (value: string) => void;
  language?: string;
  readOnly?: boolean;
  height?: string;
  maxVisibleLines?: number;
}

// Enhanced code editor component with improved features
export default function CodeEditor({
  value,
  onChange,
  language = "javascript",
  readOnly = false,
  height = "500px", // Increased default height
  maxVisibleLines = 200 // Show up to 200 line numbers by default
}: CodeEditorProps) {
  const [lineCount, setLineCount] = useState<number>(value.split('\n').length);
  const [scrollPosition, setScrollPosition] = useState<number>(0);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const lineNumbersRef = useRef<HTMLDivElement>(null);
  
  // Handle syncing scroll between line numbers and textarea
  useEffect(() => {
    const textarea = textareaRef.current;
    if (!textarea) return;
    
    const handleScroll = () => {
      if (lineNumbersRef.current) {
        lineNumbersRef.current.scrollTop = textarea.scrollTop;
      }
      setScrollPosition(textarea.scrollTop);
    };
    
    textarea.addEventListener('scroll', handleScroll);
    return () => textarea.removeEventListener('scroll', handleScroll);
  }, []);

  // Recalculate line count when value changes
  useEffect(() => {
    setLineCount(value.split('\n').length);
  }, [value]);

  const handleChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const newValue = e.target.value;
    onChange(newValue);
    setLineCount(newValue.split('\n').length);
  };

  // Detect tab key press and insert tabs instead of changing focus
  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Tab') {
      e.preventDefault();
      const textarea = e.currentTarget;
      const start = textarea.selectionStart;
      const end = textarea.selectionEnd;
      
      // Insert tab at cursor position or indent selected text
      const newValue = 
        value.substring(0, start) + 
        '  ' + // 2 space indentation
        value.substring(end);
      
      onChange(newValue);
      
      // Set cursor position after the inserted tab
      setTimeout(() => {
        textarea.selectionStart = textarea.selectionEnd = start + 2;
      }, 0);
    }
  };

  // Generate the array of line numbers to display
  const generateLineNumbers = () => {
    const totalLines = Math.max(lineCount, 1);
    const visibleLines = Math.min(totalLines, maxVisibleLines);
    
    return Array.from({ length: visibleLines }, (_, i) => (
      <div key={i} className="leading-tight py-0.5">
        {i + 1}
      </div>
    ));
  };

  return (
    <div 
      className="relative overflow-hidden border border-gray-700 rounded-md bg-gray-900 font-mono"
      style={{ height }}
    >
      <div className="flex h-full">
        {/* Line numbers column */}
        <div 
          ref={lineNumbersRef}
          className="bg-gray-800 text-gray-500 p-2 text-right select-none overflow-hidden"
          style={{ 
            minWidth: lineCount > 999 ? '4rem' : '3rem',
            maxHeight: height,
            overflowY: 'hidden'
          }}
        >
          {generateLineNumbers()}
        </div>
        
        {/* Code textarea */}
        <textarea
          ref={textareaRef}
          value={value}
          onChange={handleChange}
          onKeyDown={handleKeyDown}
          readOnly={readOnly}
          className="w-full h-full p-2 bg-transparent text-gray-100 resize-none border-none outline-none"
          style={{ 
            minHeight: height,
            lineHeight: "1.5rem",
            fontFamily: "'Fira Code', monospace, Consolas, Monaco, 'Andale Mono'",
            fontSize: "14px"
          }}
          spellCheck="false"
          placeholder="// Enter your JavaScript code here..."
          wrap="off" // Prevent line wrapping
        />
      </div>
      
      {/* Status bar at bottom with info about line count */}
      <div className="absolute bottom-0 left-0 right-0 bg-gray-800 text-gray-400 text-xs px-2 py-1 flex justify-between border-t border-gray-700">
        <span>{lineCount} lines</span>
        <span>JavaScript</span>
      </div>
    </div>
  );
}
