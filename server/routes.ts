import express, { type Express, Request, Response, NextFunction } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { 
  scanRequestSchema, 
  ScanResult, 
  codeFixRequestSchema, 
  CodeFixRequest, 
  CodeFixResponse
} from "@shared/schema";
import { scanJavaScriptCode } from "./scanner";
import { generateFixedCode } from "./scanner/code-fixer";

export async function registerRoutes(app: Express): Promise<Server> {
  // API routes for the XSS scanner
  const apiRouter = express.Router();

  // Endpoint to scan JavaScript code for XSS vulnerabilities
  apiRouter.post("/scan", async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Validate request body using Zod schema
      const validatedData = scanRequestSchema.parse(req.body);
      
      // Scan the code for vulnerabilities
      const result: ScanResult = await scanJavaScriptCode(validatedData.code);
      
      // Add autoFixable flag to each vulnerability
      const enhancedResult = {
        ...result,
        vulnerabilities: result.vulnerabilities.map(vuln => ({
          ...vuln,
          autoFixable: isAutoFixableVulnerability(vuln.type)
        }))
      };
      
      res.json(enhancedResult);
    } catch (error) {
      next(error);
    }
  });
  
  // Endpoint to automatically fix vulnerable code
  apiRouter.post("/fix", async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Validate request body
      const fixRequest: CodeFixRequest = codeFixRequestSchema.parse(req.body);
      
      // Generate fixed code
      const fixResult: CodeFixResponse = await generateFixedCode(fixRequest);
      
      res.json(fixResult);
    } catch (error) {
      next(error);
    }
  });

  // Prefix all routes with /api
  app.use("/api", apiRouter);

  const httpServer = createServer(app);

  return httpServer;
}

/**
 * Determines if a vulnerability type can be automatically fixed
 */
function isAutoFixableVulnerability(type: string): boolean {
  // List of vulnerability types that can be automatically fixed
  const autoFixableTypes = [
    // DOM-based XSS
    "innerHTML", "outerHTML", "insertAdjacentHTML", "documentWrite", 
    "documentWriteLn", "dangerouslySetInnerHTML",
    
    // Code execution vulnerabilities
    "eval", "functionConstructor", "setTimeout", "setInterval", "indirectEval",
    
    // Template-based vulnerabilities
    "templateLiteralInjection", "clientTemplateInjection",
    
    // Parser and sanitization vulnerabilities
    "jsonParseVulnerability", "domParserVulnerability", 
    "sanitizationBypass", "mutationXSS",
    
    // Other vulnerability types
    "scriptSrcAssignment", "domClobbering", "directMetaTagContentAssignment"
  ];
  
  return autoFixableTypes.includes(type);
}
