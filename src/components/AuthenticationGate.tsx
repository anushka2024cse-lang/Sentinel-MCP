import React, { FormEvent, useEffect, useState } from 'react';
import { ShieldCheck } from 'lucide-react';
import { api, ApiSession } from '../services/api.js';

interface AuthenticationGateProps {
  children: (session: ApiSession, onLogout: () => void) => React.ReactNode;
}

export const AuthenticationGate: React.FC<AuthenticationGateProps> = ({ children }) => {
  const [session, setSession] = useState<ApiSession | null>(null);
  const [token, setToken] = useState('');
  const [error, setError] = useState('');
  const [isChecking, setIsChecking] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    api.getSession()
      .then(setSession)
      .catch(() => {
        api.clearAccessToken();
      })
      .finally(() => setIsChecking(false));
  }, []);

  const handleLogin = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError('');
    setIsSubmitting(true);
    api.setAccessToken(token.trim());
    try {
      setSession(await api.getSession());
      setToken('');
    } catch (loginError) {
      api.clearAccessToken();
      setError(loginError instanceof Error ? loginError.message : 'Authentication failed.');
    } finally {
      setIsSubmitting(false);
    }
  };

  if (isChecking) {
    return <div className="min-h-screen bg-[#080D18]" aria-label="Checking authentication" />;
  }

  if (session) {
    return <>{children(session, () => {
      api.clearAccessToken();
      setSession(null);
    })}</>;
  }

  return (
    <main className="min-h-screen bg-[#080D18] text-slate-100 flex items-center justify-center p-6">
      <form onSubmit={handleLogin} className="w-full max-w-md rounded-xl border border-slate-800 bg-[#0F172A] p-7 space-y-5">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-blue-600/20 border border-blue-500/40 flex items-center justify-center text-blue-400">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <h1 className="font-bold tracking-wider">SENTINEL-MCP</h1>
            <p className="text-xs text-slate-400">Authenticated gateway access</p>
          </div>
        </div>

        <div className="space-y-2">
          <label htmlFor="api-token" className="block text-sm font-medium text-slate-200">API access token</label>
          <input
            id="api-token"
            type="password"
            autoComplete="current-password"
            value={token}
            onChange={(event) => setToken(event.target.value)}
            required
            className="w-full rounded-lg border border-slate-700 bg-[#080D18] px-3 py-2.5 text-sm text-slate-100 focus:border-blue-500 focus:outline-none"
            placeholder="Paste the server-configured bearer token"
          />
          <p className="text-xs text-slate-400">
            For a local development run, use the temporary token printed in the VS Code terminal.
          </p>
        </div>

        {error && <p role="alert" className="text-sm text-red-400">{error}</p>}

        <button
          type="submit"
          disabled={isSubmitting || !token.trim()}
          className="w-full rounded-lg bg-blue-600 px-4 py-2.5 text-sm font-semibold text-white hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {isSubmitting ? 'Verifying…' : 'Sign in'}
        </button>
      </form>
    </main>
  );
};
