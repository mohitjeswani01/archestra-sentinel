/**
 * Diagnostic script to test backend API connectivity
 * Run this in the browser console to verify all endpoints are working
 */

const API_URL = "http://localhost:8000/api/v1";
const timeout = 5000;

async function testEndpoint(name, endpoint) {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);
    
    const response = await fetch(`${API_URL}${endpoint}`, {
      signal: controller.signal
    });
    
    clearTimeout(timeoutId);
    
    if (response.ok) {
      const data = await response.json();
      console.log(`✅ ${name}: SUCCESS`);
      return { success: true, data };
    } else {
      console.error(`❌ ${name}: HTTP ${response.status}`);
      return { success: false, status: response.status };
    }
  } catch (error) {
    console.error(`❌ ${name}: ${error.message}`);
    return { success: false, error: error.message };
  }
}

async function runDiagnostics() {
  console.log("🔍 Archestra Sentinel API Diagnostics");
  console.log("=" .repeat(50));
  
  const results = await Promise.all([
    testEndpoint("System Health", "/system/health"),
    testEndpoint("Discovery (Shadow AI)", "/discovery/shadow-ai"),
    testEndpoint("Metrics Summary", "/metrics/summary"),
    testEndpoint("Security Alerts", "/security/alerts"),
    testEndpoint("Governance Audit Logs", "/governance/audit-logs"),
  ]);
  
  console.log("\n📊 Results:");
  console.log("=" .repeat(50));
  
  const passed = results.filter(r => r.success).length;
  const total = results.length;
  
  console.log(`Passed: ${passed}/${total}`);
  
  if (passed === total) {
    console.log("\n✅ All endpoints are working! Refresh the page to reload data.");
  } else {
    console.log("\n⚠️ Some endpoints are failing. Check the errors above.");
  }
}

// Run diagnostics
runDiagnostics();
