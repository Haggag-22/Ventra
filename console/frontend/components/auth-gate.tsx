"use client";

import { AUTH_REQUIRED_EVENT } from "@/lib/api";
import { Button } from "@/components/ui";
import { KeyRound } from "lucide-react";
import { useEffect, useState, type FormEvent } from "react";

/**
 * Full-screen notice shown when the API answers 401: this browser has no console session.
 * The launcher's sign-in link sets one; pasting the token here does the same.
 */
export function AuthGate() {
  const [locked, setLocked] = useState(false);
  const [token, setToken] = useState("");

  useEffect(() => {
    const onLocked = () => setLocked(true);
    window.addEventListener(AUTH_REQUIRED_EVENT, onLocked);
    return () => window.removeEventListener(AUTH_REQUIRED_EVENT, onLocked);
  }, []);

  if (!locked) return null;

  const signIn = (e: FormEvent) => {
    e.preventDefault();
    const value = token.trim();
    if (!value) return;
    const next = `${window.location.pathname}${window.location.search}`;
    window.location.assign(
      `/api/session?${new URLSearchParams({ token: value, next }).toString()}`,
    );
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="auth-gate-title"
      className="fixed inset-0 z-[100] flex items-center justify-center bg-bg/95 px-4 backdrop-blur-sm"
    >
      <form
        onSubmit={signIn}
        className="w-full max-w-md rounded-xl border border-border bg-surface p-6 shadow-xl"
      >
        <div className="mb-3 flex items-center gap-2">
          <KeyRound className="h-5 w-5 text-accent" aria-hidden />
          <h1 id="auth-gate-title" className="text-base font-semibold text-fg">
            Console locked
          </h1>
        </div>
        <p className="text-sm text-fg-subtle">
          Open the <span className="font-medium text-fg">Sign in</span> link that{" "}
          <code className="mono rounded bg-surface-2 px-1">ventra gui</code> printed in your
          terminal, or run{" "}
          <code className="mono rounded bg-surface-2 px-1">ventra gui --print-link</code> to see it
          again. You can also paste the token from that link here.
        </p>
        <label htmlFor="auth-gate-token" className="mt-4 block text-xs font-medium text-fg-subtle">
          Console token
        </label>
        <input
          id="auth-gate-token"
          type="password"
          autoComplete="off"
          autoFocus
          value={token}
          onChange={(e) => setToken(e.target.value)}
          className="ct-input ct-input-full mt-1"
        />
        <div className="mt-4 flex justify-end">
          <Button type="submit" variant="primary" icon={KeyRound} disabled={!token.trim()}>
            Unlock
          </Button>
        </div>
      </form>
    </div>
  );
}
