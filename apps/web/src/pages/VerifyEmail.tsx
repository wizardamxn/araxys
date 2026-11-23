import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { Mail, ArrowRight, Loader2, AlertCircle } from "@/components/icons";
import { useEffect, useState } from "react";
import { useResendCode, useVerifyEmail } from "@/api/auth";
import { errorMessage } from "@/lib/api";
import { nextPath } from "@/lib/nextPath";
import { toast } from "sonner";
import AuthShell from "@/components/AuthShell";
import { HoverBorderGradient } from "@/components/ace/hover-border-gradient";

const RESEND_SECONDS = 60;

export default function VerifyEmail() {
  const verify = useVerifyEmail();
  const resend = useResendCode();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const email = params.get("email") ?? "";
  const next = nextPath();

  const [code, setCode] = useState("");
  const [error, setError] = useState(email ? "" : "This link is missing the email address. Sign up or log in again.");
  const [cooldown, setCooldown] = useState(RESEND_SECONDS); // a code was just sent

  useEffect(() => {
    if (cooldown <= 0) return;
    const t = setTimeout(() => setCooldown((s) => s - 1), 1000);
    return () => clearTimeout(t);
  }, [cooldown]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    verify.mutate(
      { email, code },
      {
        onSuccess: () => {
          toast.success("Email verified. Welcome to Araxys!");
          navigate(next ?? "/onboarding", { replace: true });
        },
        onError: (err) => setError(errorMessage(err, "That code didn't work. Please try again.")),
      },
    );
  };

  const handleResend = () => {
    setError("");
    resend.mutate(email, {
      onSuccess: () => {
        toast.success("A new code is on its way.");
        setCooldown(RESEND_SECONDS);
      },
      onError: (err) => setError(errorMessage(err, "Couldn't send a new code. Please try again.")),
    });
  };

  return (
    <AuthShell>
      <div className="mb-8 flex flex-col items-center text-center">
        <h1 className="text-3xl font-bold tracking-tight text-white">Check your email</h1>
        <p className="mt-2 text-sm text-zinc-400">
          We sent a 6-digit code to <span className="font-medium text-zinc-200">{email || "your inbox"}</span>
        </p>
      </div>

      <div className="glass-card p-6 shadow-2xl">
        {error && (
          <div role="alert" className="mb-4 flex items-start gap-3 rounded-lg border border-red-500/20 bg-red-500/10 p-3">
            <AlertCircle className="mt-0.5 h-5 w-5 shrink-0 text-red-500" />
            <p className="text-sm text-red-200">{error}</p>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-1.5">
            <label htmlFor="otp" className="text-xs font-medium uppercase tracking-wider text-zinc-400">
              Verification code
            </label>
            <div className="group relative">
              <Mail className="absolute left-3 top-3 h-4 w-4 text-zinc-500 transition-colors group-focus-within:text-emerald-400" />
              <input
                id="otp"
                inputMode="numeric"
                autoComplete="one-time-code"
                autoFocus
                maxLength={6}
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                className="w-full rounded-lg border border-white/10 bg-zinc-950/50 py-2 pl-10 pr-4 font-mono text-lg tracking-[0.5em] text-white outline-none transition-all placeholder:text-zinc-700 focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50"
                placeholder="000000"
                required
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={verify.isPending || code.length !== 6 || !email}
            className="w-full disabled:cursor-not-allowed disabled:opacity-60"
          >
            <HoverBorderGradient
              as="span"
              containerClassName="w-full"
              className="flex w-full items-center justify-center gap-2 py-3 text-sm font-semibold"
            >
              {verify.isPending ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Verifying…
                </>
              ) : (
                <>
                  Verify email
                  <ArrowRight className="h-4 w-4" />
                </>
              )}
            </HoverBorderGradient>
          </button>
        </form>

        <p className="mt-4 text-center text-sm text-zinc-500" aria-live="polite">
          Didn't get it?{" "}
          <button
            type="button"
            onClick={handleResend}
            disabled={cooldown > 0 || resend.isPending || !email}
            className="font-medium text-emerald-400 transition-colors hover:text-emerald-300 disabled:cursor-not-allowed disabled:text-zinc-600"
          >
            {cooldown > 0 ? `Resend in ${cooldown}s` : "Send a new code"}
          </button>
        </p>
      </div>

      <p className="mt-6 text-center text-sm text-zinc-500">
        Wrong email?{" "}
        <Link to="/signup" className="font-medium text-emerald-400 transition-colors hover:text-emerald-300">
          Sign up again
        </Link>
      </p>
    </AuthShell>
  );
}
