import { pgTable, text, serial, integer, boolean, jsonb } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const users = pgTable("users", {
  id: serial("id").primaryKey(),
  username: text("username").notNull().unique(),
  password: text("password").notNull(),
});

export const insertUserSchema = createInsertSchema(users).pick({
  username: true,
  password: true,
});

export type InsertUser = z.infer<typeof insertUserSchema>;
export type User = typeof users.$inferSelect;

// Schema for XSS vulnerability scan results
export const vulnerabilitySchema = z.object({
  id: z.string(),
  type: z.string(),
  severity: z.enum(["critical", "high", "medium", "low", "info"]),
  title: z.string(),
  description: z.string(),
  line: z.number().optional(),
  column: z.number().optional(),
  code: z.string(),
  recommendation: z.string(),
  recommendationCode: z.string().optional(),
});

export type Vulnerability = z.infer<typeof vulnerabilitySchema>;

export const scanResultSchema = z.object({
  vulnerabilities: z.array(vulnerabilitySchema),
  summary: z.object({
    critical: z.number(),
    high: z.number(),
    medium: z.number(),
    low: z.number(),
    info: z.number(),
    passedChecks: z.number(),
    total: z.number().optional(),
    uniqueTypes: z.number().optional()
  }),
  scannedAt: z.string(),
});

export type ScanResult = z.infer<typeof scanResultSchema>;

export const scanRequestSchema = z.object({
  code: z.string(),
  fileName: z.string().optional(),
});

export type ScanRequest = z.infer<typeof scanRequestSchema>;
