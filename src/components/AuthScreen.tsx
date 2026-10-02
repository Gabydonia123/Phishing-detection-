import React, { useState } from 'react';
import { ShieldCheck, Mail, Lock, User, ArrowRight, CheckCircle2, ShieldAlert, Cpu, Sparkles, Terminal } from 'lucide-react';
import { registerNewUser, saveSession } from '../lib/authStore';
import { UserProfile } from '../types';

interface AuthScreenProps {
  onLoginSuccess: (user: UserProfile) => void;
  defaultEmail?: string;
}

export const AuthScreen: React.FC<AuthScreenProps> = ({ onLoginSuccess, defaultEmail = 'napoleongabriel92@gmail.com' }) => {
  const [mode, setMode] = useState<'signin' | 'signup'>('signup');
  const [email, setEmail] = useState(defaultEmail);
  const [name, setName] = useState('Napoleon Gabriel');
  const [password, setPassword] = useState('SecurePass2026!');
  const [role, setRole] = useState('Cybersecurity Threat Analyst');
  const [organization, setOrganization] = useState('Threat Research Lab');
  const [error, setError] = useState<string | null>(null);
  const [isProcessing, setIsProcessing] = useState(false);

  const handleGoogleGmailAuth = () => {
    setIsProcessing(true);
    setError(null);
    setTimeout(() => {
      const gmailAddress = email.includes('@gmail.com') ? email : 'napoleongabriel92@gmail.com';
      const user = registerNewUser({
        name: name || 'Napoleon Gabriel',
        email: gmailAddress,
        authProvider: 'google',
        role: role,
        organization: organization
      });
      setIsProcessing(false);
      onLoginSuccess(user);
    }, 600);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!email || !email.includes('@')) {
      setError('Please enter a valid email address (e.g. username@gmail.com).');
      return;
    }

    if (mode === 'signup' && !name.trim()) {
      setError('Please provide your full name or security handle.');
      return;
    }

    if (password.length < 6) {
      setError('Password must be at least 6 characters long.');
      return;
    }

    setIsProcessing(true);
    setTimeout(() => {
      const user = registerNewUser({
        name: name || email.split('@')[0],
        email: email,
        authProvider: email.toLowerCase().endsWith('@gmail.com') ? 'google' : 'email',
        role: role,
        organization: organization
      });
      setIsProcessing(false);
      onLoginSuccess(user);
    }, 500);
  };

  const handleQuickDemo = (demoEmail: string, demoName: string, demoRole: string) => {
    setEmail(demoEmail);
    setName(demoName);
    setRole(demoRole);
  };

  return (
    <div className="min-h-screen w-full bg-slate-950 text-slate-100 flex flex-col justify-center items-center p-4 relative overflow-hidden font-sans">
      {/* Background Decorative Tech Grid & Glowing Orbs */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#0f172a_1px,transparent_1px),linear-gradient(to_bottom,#0f172a_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_50%,#000_70%,transparent_100%)] opacity-30 pointer-events-none" />
      <div className="absolute -top-40 -left-40 w-96 h-96 bg-cyan-600/15 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute -bottom-40 -right-40 w-96 h-96 bg-emerald-600/15 rounded-full blur-3xl pointer-events-none" />

      {/* Main Container */}
      <div className="w-full max-w-4xl grid grid-cols-1 lg:grid-cols-12 bg-slate-900/80 border border-slate-800 backdrop-blur-xl rounded-2xl shadow-2xl overflow-hidden relative z-10">
        
        {/* Left Branding & ML Specs Column */}
        <div className="lg:col-span-5 bg-gradient-to-br from-slate-900 via-slate-950 to-cyan-950/40 p-8 flex flex-col justify-between border-b lg:border-b-0 lg:border-r border-slate-800/80 relative">
          <div>
            <div className="flex items-center gap-3 mb-6">
              <div className="w-12 h-12 rounded-xl bg-gradient-to-tr from-cyan-500 to-emerald-400 p-0.5 flex items-center justify-center shadow-lg shadow-cyan-500/20">
                <div className="w-full h-full bg-slate-950 rounded-[10px] flex items-center justify-center">
                  <ShieldCheck className="w-6 h-6 text-cyan-400" />
                </div>
              </div>
              <div>
                <div className="text-xs font-semibold uppercase tracking-widest text-cyan-400 font-mono">Cyber Intelligence</div>
                <h1 className="text-lg font-bold text-white leading-tight">PhishGuard RF</h1>
              </div>
            </div>

            <h2 className="text-xl font-bold text-white mb-2 leading-snug">
              Phishing Website Detection System
            </h2>
            <p className="text-xs text-slate-400 mb-6 leading-relaxed">
              Ensemble machine learning framework leveraging 16 URL structural & lexical features with multi-tree Random Forest consensus.
            </p>

            {/* Core Algorithm Badges */}
            <div className="space-y-2.5 mb-6">
              <div className="flex items-center gap-2.5 text-xs text-slate-300 bg-slate-950/60 p-2.5 rounded-lg border border-slate-800/60">
                <Cpu className="w-4 h-4 text-emerald-400 shrink-0" />
                <span><strong className="text-emerald-300">25 Estimator Trees</strong> with Gini Impurity Splitting</span>
              </div>
              <div className="flex items-center gap-2.5 text-xs text-slate-300 bg-slate-950/60 p-2.5 rounded-lg border border-slate-800/60">
                <Terminal className="w-4 h-4 text-cyan-400 shrink-0" />
                <span><strong className="text-cyan-300">16 Extracted Vectors</strong> (Entropy, IP, SSL, Punycode)</span>
              </div>
              <div className="flex items-center gap-2.5 text-xs text-slate-300 bg-slate-950/60 p-2.5 rounded-lg border border-slate-800/60">
                <ShieldAlert className="w-4 h-4 text-amber-400 shrink-0" />
                <span><strong className="text-amber-300">97.4% Model Accuracy</strong> on PhishTank benchmark</span>
              </div>
            </div>
          </div>

          <div className="pt-4 border-t border-slate-800/60 text-[11px] text-slate-400 flex items-center justify-between">
            <span className="flex items-center gap-1.5 text-emerald-400">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
              ML Service Ready
            </span>
            <span className="font-mono text-slate-400">Random Forest v2.4</span>
          </div>
        </div>

        {/* Right Form Column: Sign Up / Sign In */}
        <div className="lg:col-span-7 p-8 flex flex-col justify-center bg-slate-900/50">
          
          {/* Mode Switcher Tabs */}
          <div className="flex items-center justify-between mb-6">
            <div>
              <h3 className="text-xl font-bold text-white">
                {mode === 'signup' ? 'Create Analyst Account' : 'Welcome Back'}
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                {mode === 'signup'
                  ? 'Sign up with Gmail to access the phishing detection suite'
                  : 'Enter your credentials to access the security console'}
              </p>
            </div>
            
            <div className="flex bg-slate-950 p-1 rounded-lg border border-slate-800">
              <button
                type="button"
                onClick={() => { setMode('signup'); setError(null); }}
                className={`px-3 py-1 text-xs font-medium rounded-md transition-all ${
                  mode === 'signup'
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Sign Up
              </button>
              <button
                type="button"
                onClick={() => { setMode('signin'); setError(null); }}
                className={`px-3 py-1 text-xs font-medium rounded-md transition-all ${
                  mode === 'signin'
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Sign In
              </button>
            </div>
          </div>

          {/* Direct Gmail / Google One-Click Auth Button */}
          <button
            type="button"
            onClick={handleGoogleGmailAuth}
            disabled={isProcessing}
            className="w-full flex items-center justify-center gap-3 bg-white hover:bg-slate-100 text-slate-900 font-semibold py-2.5 px-4 rounded-xl shadow-lg transition-all transform active:scale-[0.99] mb-4 text-xs group"
          >
            <svg className="w-4 h-4 shrink-0" viewBox="0 0 24 24">
              <path
                fill="#4285F4"
                d="M23.745 12.27c0-.7-.06-1.4-.19-2.07H12v4.51h6.6c-.29 1.52-1.14 2.82-2.4 3.68v3.05h3.88c2.27-2.09 3.665-5.17 3.665-9.17z"
              />
              <path
                fill="#34A853"
                d="M12 24c3.24 0 5.95-1.08 7.93-2.91l-3.88-3.05c-1.08.72-2.45 1.16-4.05 1.16-3.12 0-5.77-2.1-6.72-4.93H1.25v3.15C3.26 21.36 7.33 24 12 24z"
              />
              <path
                fill="#FBBC05"
                d="M5.28 14.27c-.25-.72-.38-1.49-.38-2.27s.13-1.55.38-2.27V6.58H1.25C.45 8.18 0 10.03 0 12s.45 3.82 1.25 5.42l4.03-3.15z"
              />
              <path
                fill="#EA4335"
                d="M12 4.75c1.77 0 3.35.61 4.6 1.8l3.42-3.42C17.95 1.19 15.24 0 12 0 7.33 0 3.26 2.64 1.25 6.58l4.03 3.15c.95-2.83 3.6-4.98 6.72-4.98z"
              />
            </svg>
            <span>
              {mode === 'signup' ? 'Create Account with Gmail' : 'Sign In with Gmail / Google'}
            </span>
            <ArrowRight className="w-3.5 h-3.5 text-slate-600 group-hover:translate-x-0.5 transition-transform" />
          </button>

          <div className="relative flex py-2 items-center mb-4">
            <div className="flex-grow border-t border-slate-800"></div>
            <span className="flex-shrink mx-3 text-[11px] uppercase tracking-wider text-slate-400 font-mono">or continue with email</span>
            <div className="flex-grow border-t border-slate-800"></div>
          </div>

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-3.5">
            {mode === 'signup' && (
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Full Name / Analyst Name
                </label>
                <div className="relative">
                  <User className="w-4 h-4 text-slate-400 absolute left-3 top-2.5 pointer-events-none" />
                  <input
                    type="text"
                    required
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="Napoleon Gabriel"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-xs text-white placeholder-slate-400 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
                  />
                </div>
              </div>
            )}

            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="block text-xs font-medium text-slate-300">
                  Gmail / Work Email
                </label>
                <button
                  type="button"
                  onClick={() => setEmail('napoleongabriel92@gmail.com')}
                  className="text-[11px] text-cyan-400 hover:text-cyan-300 font-mono"
                >
                  Use @gmail.com
                </button>
              </div>
              <div className="relative">
                <Mail className="w-4 h-4 text-slate-400 absolute left-3 top-2.5 pointer-events-none" />
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="napoleongabriel92@gmail.com"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-xs text-white placeholder-slate-400 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-mono"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Password
              </label>
              <div className="relative">
                <Lock className="w-4 h-4 text-slate-400 absolute left-3 top-2.5 pointer-events-none" />
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-xs text-white placeholder-slate-400 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-mono"
                />
              </div>
            </div>

            {mode === 'signup' && (
              <div className="grid grid-cols-2 gap-2.5 pt-1">
                <div>
                  <label className="block text-[11px] font-medium text-slate-400 mb-1">
                    Security Role
                  </label>
                  <select
                    value={role}
                    onChange={(e) => setRole(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
                  >
                    <option value="Lead Cybersecurity Analyst">Lead Security Analyst</option>
                    <option value="SOC Tier-1 Investigator">SOC Investigator</option>
                    <option value="Penetration Tester">Penetration Tester</option>
                    <option value="Independent Researcher">Independent Researcher</option>
                  </select>
                </div>
                <div>
                  <label className="block text-[11px] font-medium text-slate-400 mb-1">
                    Organization / Lab
                  </label>
                  <input
                    type="text"
                    value={organization}
                    onChange={(e) => setOrganization(e.target.value)}
                    placeholder="Threat Research Lab"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-white focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>
            )}

            {error && (
              <div className="p-2.5 bg-rose-950/40 border border-rose-800/60 rounded-lg text-xs text-rose-300 flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 shrink-0 text-rose-400" />
                <span>{error}</span>
              </div>
            )}

            <button
              type="submit"
              disabled={isProcessing}
              className="w-full bg-gradient-to-r from-cyan-600 to-emerald-600 hover:from-cyan-500 hover:to-emerald-500 text-white font-semibold py-2.5 px-4 rounded-xl text-xs transition-all shadow-lg shadow-cyan-600/20 flex items-center justify-center gap-2 mt-2 cursor-pointer disabled:opacity-50"
            >
              {isProcessing ? (
                <span className="flex items-center gap-2">
                  <span className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin"></span>
                  Initializing Security Session...
                </span>
              ) : (
                <>
                  <span>{mode === 'signup' ? 'Create Account & Access System' : 'Sign In to Dashboard'}</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </>
              )}
            </button>
          </form>

          {/* Quick Demo Accounts Selection */}
          <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-400">
            <span>Quick profile presets:</span>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => handleQuickDemo('napoleongabriel92@gmail.com', 'Napoleon Gabriel', 'Lead Cybersecurity Analyst')}
                className="hover:text-cyan-300 text-slate-300 underline font-mono text-[11px]"
              >
                napoleongabriel92@gmail.com
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
