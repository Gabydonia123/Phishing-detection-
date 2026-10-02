import React from 'react';
import {
  ShieldCheck,
  Search,
  Layers,
  Cpu,
  History,
  Sliders,
  LogOut,
  Sparkles,
  Activity,
  Terminal,
  ExternalLink
} from 'lucide-react';
import { UserProfile } from '../types';

export type ActiveTab = 'single-scanner' | 'batch-scanner' | 'model-studio' | 'threat-lab' | 'history';

interface HeaderProps {
  activeTab: ActiveTab;
  setActiveTab: (tab: ActiveTab) => void;
  user: UserProfile;
  onLogout: () => void;
  totalScansCount: number;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  setActiveTab,
  user,
  onLogout,
  totalScansCount
}) => {
  return (
    <header className="sticky top-0 z-40 w-full bg-slate-950/80 backdrop-blur-md border-b border-slate-800">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          
          {/* Logo & System Brand */}
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-500 to-emerald-500 p-0.5 flex items-center justify-center shadow-md shadow-cyan-500/20">
              <div className="w-full h-full bg-slate-950 rounded-[10px] flex items-center justify-center">
                <ShieldCheck className="w-5 h-5 text-cyan-400" />
              </div>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-sm font-bold tracking-tight text-white font-mono">
                  PhishGuard<span className="text-cyan-400">.RF</span>
                </span>
                <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-mono">
                  25 Trees Active
                </span>
              </div>
              <p className="text-[10px] text-slate-400 hidden sm:block">
                Random Forest Phishing Intelligence System
              </p>
            </div>
          </div>

          {/* Nav Tabs */}
          <nav className="hidden md:flex items-center space-x-1 bg-slate-900/90 p-1 rounded-xl border border-slate-800">
            <button
              onClick={() => setActiveTab('single-scanner')}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                activeTab === 'single-scanner'
                  ? 'bg-cyan-500 text-slate-950 font-semibold shadow-sm'
                  : 'text-slate-300 hover:text-white hover:bg-slate-800/60'
              }`}
            >
              <Search className="w-3.5 h-3.5" />
              <span>URL Scanner</span>
            </button>

            <button
              onClick={() => setActiveTab('batch-scanner')}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                activeTab === 'batch-scanner'
                  ? 'bg-cyan-500 text-slate-950 font-semibold shadow-sm'
                  : 'text-slate-300 hover:text-white hover:bg-slate-800/60'
              }`}
            >
              <Layers className="w-3.5 h-3.5" />
              <span>Batch Scanner</span>
            </button>

            <button
              onClick={() => setActiveTab('model-studio')}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                activeTab === 'model-studio'
                  ? 'bg-cyan-500 text-slate-950 font-semibold shadow-sm'
                  : 'text-slate-300 hover:text-white hover:bg-slate-800/60'
              }`}
            >
              <Cpu className="w-3.5 h-3.5" />
              <span>Random Forest Studio</span>
            </button>

            <button
              onClick={() => setActiveTab('threat-lab')}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                activeTab === 'threat-lab'
                  ? 'bg-cyan-500 text-slate-950 font-semibold shadow-sm'
                  : 'text-slate-300 hover:text-white hover:bg-slate-800/60'
              }`}
            >
              <Sliders className="w-3.5 h-3.5" />
              <span>Feature Lab</span>
            </button>

            <button
              onClick={() => setActiveTab('history')}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-all relative ${
                activeTab === 'history'
                  ? 'bg-cyan-500 text-slate-950 font-semibold shadow-sm'
                  : 'text-slate-300 hover:text-white hover:bg-slate-800/60'
              }`}
            >
              <History className="w-3.5 h-3.5" />
              <span>History</span>
              {totalScansCount > 0 && (
                <span className="ml-0.5 px-1.5 py-0.2 rounded-full text-[10px] bg-slate-950 text-cyan-400 font-mono">
                  {totalScansCount}
                </span>
              )}
            </button>
          </nav>

          {/* User Profile & Actions */}
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2.5 bg-slate-900/80 border border-slate-800 rounded-xl px-3 py-1.5">
              <img
                src={user.avatarUrl || `https://api.dicebear.com/7.x/initials/svg?seed=${encodeURIComponent(user.name)}`}
                alt={user.name}
                className="w-7 h-7 rounded-lg ring-1 ring-cyan-500/40 object-cover bg-slate-800"
              />
              <div className="text-left hidden sm:block">
                <div className="text-xs font-semibold text-white leading-tight flex items-center gap-1.5">
                  <span>{user.name}</span>
                  {user.authProvider === 'google' && (
                    <span className="text-[9px] bg-blue-500/10 text-blue-400 px-1 py-0.2 rounded border border-blue-500/20 font-mono">
                      Gmail
                    </span>
                  )}
                </div>
                <div className="text-[10px] text-slate-400 font-mono truncate max-w-[140px]">
                  {user.email}
                </div>
              </div>
              <button
                onClick={onLogout}
                title="Sign out of security session"
                className="p-1 text-slate-400 hover:text-rose-400 hover:bg-rose-950/40 rounded-lg transition-colors ml-1"
              >
                <LogOut className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>

        {/* Mobile Sub Navigation */}
        <div className="flex md:hidden overflow-x-auto space-x-1 py-2 border-t border-slate-800/60 no-scrollbar">
          <button
            onClick={() => setActiveTab('single-scanner')}
            className={`px-3 py-1 rounded-lg text-xs whitespace-nowrap font-medium ${
              activeTab === 'single-scanner' ? 'bg-cyan-500 text-slate-950' : 'text-slate-400'
            }`}
          >
            URL Scanner
          </button>
          <button
            onClick={() => setActiveTab('batch-scanner')}
            className={`px-3 py-1 rounded-lg text-xs whitespace-nowrap font-medium ${
              activeTab === 'batch-scanner' ? 'bg-cyan-500 text-slate-950' : 'text-slate-400'
            }`}
          >
            Batch Scan
          </button>
          <button
            onClick={() => setActiveTab('model-studio')}
            className={`px-3 py-1 rounded-lg text-xs whitespace-nowrap font-medium ${
              activeTab === 'model-studio' ? 'bg-cyan-500 text-slate-950' : 'text-slate-400'
            }`}
          >
            RF Studio
          </button>
          <button
            onClick={() => setActiveTab('threat-lab')}
            className={`px-3 py-1 rounded-lg text-xs whitespace-nowrap font-medium ${
              activeTab === 'threat-lab' ? 'bg-cyan-500 text-slate-950' : 'text-slate-400'
            }`}
          >
            Feature Lab
          </button>
          <button
            onClick={() => setActiveTab('history')}
            className={`px-3 py-1 rounded-lg text-xs whitespace-nowrap font-medium ${
              activeTab === 'history' ? 'bg-cyan-500 text-slate-950' : 'text-slate-400'
            }`}
          >
            History ({totalScansCount})
          </button>
        </div>
      </div>
    </header>
  );
};
