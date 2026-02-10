import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { loginWithSSO } from "@/services/serviceApi";
import { motion } from "framer-motion";
import { Shield, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";

export default function LoginPage() {
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSSO = async () => {
    setLoading(true);
    try {
      const { token, user } = await loginWithSSO();
      localStorage.setItem("auth_token", token);
      localStorage.setItem("auth_user", JSON.stringify(user));
      toast.success(`Welcome back, ${user.name}`, { description: user.role });
      navigate("/dashboard");
    } catch {
      toast.error("SSO authentication failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-4">
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.4 }}
        className="w-full max-w-md"
      >
        <div className="glass-panel glow-border rounded-2xl p-8 text-center">
          {/* Logo */}
          <div className="flex justify-center mb-6">
            <div className="h-16 w-16 gradient-cyber rounded-xl flex items-center justify-center">
              <Shield className="h-8 w-8 text-cyber-foreground" />
            </div>
          </div>

          <h1 className="text-2xl font-bold tracking-tight mb-1">ARCHESTRA SENTINEL</h1>
          <p className="text-muted-foreground text-sm mb-8">AI Governance Control Plane</p>

          {/* SSO Button */}
          <Button
            onClick={handleSSO}
            disabled={loading}
            className="w-full h-12 gradient-cyber text-cyber-foreground font-semibold text-sm tracking-wide hover:opacity-90 transition-opacity"
          >
            {loading ? (
              <>
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                Authenticating via Corporate IdP...
              </>
            ) : (
              <>
                <Shield className="h-4 w-4 mr-2" />
                Sign in with Corporate SSO
              </>
            )}
          </Button>

          <p className="text-xs text-muted-foreground mt-6">
            Protected by SAML 2.0 • SOC 2 Type II Certified
          </p>

          {/* Security badges */}
          <div className="flex items-center justify-center gap-4 mt-4">
            {["NIST AI RMF", "ISO 27001", "FedRAMP"].map((badge) => (
              <span key={badge} className="text-[10px] font-mono text-muted-foreground/50 uppercase tracking-widest">
                {badge}
              </span>
            ))}
          </div>
        </div>
      </motion.div>
    </div>
  );
}
