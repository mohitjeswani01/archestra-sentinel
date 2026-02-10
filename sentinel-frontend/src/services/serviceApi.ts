// ─── INTERFACES ─────────────────────────────────────────────

export interface MCP_Server {
  id: string;
  name: string;
  status: "active" | "dormant" | "rogue";
  riskScore: number;
  riskLevel: "low" | "medium" | "high" | "critical";
  lastSeen: string;
  connectedAgents: number;
  toolsExposed: number;
  region: string;
  protocol: string;
}

export interface AI_Agent {
  id: string;
  name: string;
  model: string;
  status: "active" | "dormant" | "rogue";
  riskScore: number;
  riskLevel: "low" | "medium" | "high" | "critical";
  lastSeen: string;
  totalCalls: number;
  costPerDay: number;
  mcpServerId: string;
  capabilities: string[];
}

export interface Security_Alert {
  id: string;
  severity: "critical" | "high" | "medium";
  agentId: string;
  agentName: string;
  violationType: string;
  description: string;
  timestamp: string;
  status: "active" | "investigating" | "resolved";
}

export interface Cost_Analytics {
  totalSpend: number;
  totalSaved: number;
  savingsPercent: number;
  burnRate: number;
  projectedMonthly: number;
  agentCosts: { agentName: string; cost: number; trend: number }[];
  dailyBurn: { date: string; cost: number; optimized: number }[];
  optimizationInsights: { title: string; impact: string; savings: number }[];
}

export interface Audit_Log_Event {
  id: string;
  timestamp: string;
  agentId: string;
  agentName: string;
  action: string;
  tool: string;
  status: "success" | "warning" | "failed";
  details: string;
  duration: number;
}

export interface ExecutiveMetrics {
  totalAgents: number;
  activeAgents: number;
  totalServers: number;
  threatLevel: "low" | "elevated" | "high" | "critical";
  moneySaved: number;
  costReduction: number;
  alertsActive: number;
  policiesEnforced: number;
  costVsRiskTrend: { month: string; cost: number; risk: number }[];
  kpiDeltas: { label: string; value: string; delta: number; trend: "up" | "down" }[];
}

// ─── SERVICE API (imports from mocks) ───────────────────────

import {
  mockServers,
  mockAgents,
  mockAlerts,
  mockCostAnalytics,
  mockAuditLog,
  mockExecutiveMetrics,
  generateLiveLogEntry,
} from "@/mocks/mockData";

const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function getExecutiveMetrics(): Promise<ExecutiveMetrics> {
  await delay(400);
  return mockExecutiveMetrics;
}

export async function getDiscovery(): Promise<{ servers: MCP_Server[]; agents: AI_Agent[] }> {
  await delay(500);
  return { servers: mockServers, agents: mockAgents };
}

export async function getSecurityMetrics(): Promise<{ alerts: Security_Alert[]; threatLevel: string }> {
  await delay(350);
  return { alerts: mockAlerts, threatLevel: mockExecutiveMetrics.threatLevel };
}

export async function getActiveAgents(): Promise<AI_Agent[]> {
  await delay(300);
  return mockAgents.filter((a) => a.status === "active");
}

export async function getCostAnalytics(): Promise<Cost_Analytics> {
  await delay(450);
  return mockCostAnalytics;
}

export async function executeAction(actionType: string, agentId: string): Promise<{ success: boolean; message: string }> {
  await delay(800);
  if (actionType === "kill") {
    return { success: true, message: `Kill switch executed for ${agentId}. Agent terminated. All access tokens revoked.` };
  }
  return { success: true, message: `Action "${actionType}" executed on ${agentId}.` };
}

export async function getAuditLog(): Promise<Audit_Log_Event[]> {
  await delay(300);
  return mockAuditLog;
}

export async function getLatestLogs(): Promise<Audit_Log_Event[]> {
  await delay(100);
  const count = Math.random() > 0.3 ? 1 : 2;
  return Array.from({ length: count }, () => generateLiveLogEntry());
}

// ─── AUTH (mock corporate SSO) ──────────────────────────────

export async function loginWithSSO(): Promise<{ token: string; user: { name: string; role: string; email: string } }> {
  await delay(1200);
  const token = `archestra_${Date.now()}_${Math.random().toString(36).slice(2)}`;
  return {
    token,
    user: { name: "Sarah Chen", role: "Platform Engineer", email: "s.chen@archestra.io" },
  };
}

export function isAuthenticated(): boolean {
  return !!localStorage.getItem("auth_token");
}

export function getAuthUser(): { name: string; role: string; email: string } | null {
  const raw = localStorage.getItem("auth_user");
  return raw ? JSON.parse(raw) : null;
}

export function logout(): void {
  localStorage.removeItem("auth_token");
  localStorage.removeItem("auth_user");
}
