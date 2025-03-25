import { useState } from "react";

interface CodeEditorProps {
  value: string;
  onChange: (value: string) => void;
  language?: string;
  readOnly?: boolean;
}

// A simple code editor component that uses a styled textarea
export default function CodeEditor({
  value,
  onChange,
  language = "javascript",
  readOnly = false,
}: CodeEditorProps) {
  const [lineCount, setLineCount] = useState<number>(value.split('\n').length);

  const handleChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const newValue = e.target.value;
    onChange(newValue);
    setLineCount(newValue.split('\n').length);
  };

  return (
    <div className="relative h-full w-full overflow-hidden border border-gray-700 rounded-md bg-gray-900 font-mono">
      <div className="flex h-full">
        {/* Line numbers column */}
        <div className="bg-gray-800 text-gray-500 p-2 text-right select-none" style={{ minWidth: '3rem' }}>
          {Array.from({ length: Math.max(lineCount, 1) }, (_, i) => (
            <div key={i} className="leading-tight">
              {i + 1}
            </div>
          ))}
        </div>
        {/* Code textarea */}
        <textarea
          value={value}
          onChange={handleChange}
          readOnly={readOnly}
          className="w-full h-full p-2 bg-transparent text-gray-100 resize-none border-none outline-none"
          style={{ 
            minHeight: "300px",
            lineHeight: "1.5rem",
            fontFamily: "'Fira Code', monospace",
            fontSize: "14px"
          }}
          spellCheck="false"
          placeholder="// Enter your JavaScript code here..."
        />
      </div>
    </div>
  );
}
