import express, { type Express, Request, Response, NextFunction } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { scanRequestSchema, ScanResult } from "@shared/schema";
import { scanJavaScriptCode } from "./scanner";

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
      
      res.json(result);
    } catch (error) {
      next(error);
    }
  });

  // Prefix all routes with /api
  app.use("/api", apiRouter);

  const httpServer = createServer(app);

  return httpServer;
}
