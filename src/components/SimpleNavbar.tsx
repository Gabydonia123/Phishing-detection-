import React, { useState } from 'react';
import { Shield, User, LogOut, Menu, X, CheckCircle2, ChevronRight, Globe } from 'lucide-react';
import { UserProfile } from '../types';

interface SimpleNavbarProps {
  user: UserProfile | null;
  onLogout: () => void;
  onOpenLogin: () => void;
}

export const SimpleNavbar: React.FC<SimpleNavbarProps> = ({
  user,
  onLogout,
  onOpenLogin
}) => {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  return (
    <header className="sticky top-0 z-50 bg-[#0F172A] text-white border-b border-slate-800">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between">
        
        {/* Left: Mobile Hamburger & Logo */}
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="md:hidden p-1.5 text-slate-300 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
            aria-label="Toggle menu"
          >
            {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>

          <a href="#" className="flex items-center gap-2.5 group">
            <div className="w-9 h-9 bg-blue-600 rounded-lg flex items-center justify-center shadow-md shadow-blue-500/20 group-hover:bg-blue-500 transition-colors">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div className="flex flex-col">
              <span className="font-bold text-sm tracking-tight text-white flex items-center gap-1.5 font-sans">
                PHISHING DETECTION <span className="text-blue-400 font-semibold">SYSTEM</span>
              </span>
            </div>
          </a>
        </div>

        {/* Center / Desktop Links */}
        <nav className="hidden md:flex items-center space-x-6 text-xs font-medium text-slate-300">
          <a href="#checker" className="text-white hover:text-blue-400 transition-colors">
            Phishing Link Checker
          </a>
          <a href="#recent" className="hover:text-blue-400 transition-colors">
            Recent Scans
          </a>
          <a href="#about" className="hover:text-blue-400 transition-colors">
            How It Works
          </a>
        </nav>

        {/* Right: Auth / Profile Button */}
        <div className="flex items-center gap-3">
          {user ? (
            <div className="flex items-center gap-2 bg-slate-800/90 border border-slate-700/80 px-3 py-1.5 rounded-xl">
              <div className="w-6 h-6 rounded-full bg-blue-600 text-white flex items-center justify-center text-xs font-bold">
                {user.name.charAt(0).toUpperCase()}
              </div>
              <span className="text-xs font-medium text-slate-200 hidden sm:inline-block max-w-[120px] truncate">
                {user.name}
              </span>
              <button
                type="button"
                onClick={onLogout}
                title="Sign Out"
                className="ml-1 text-slate-400 hover:text-red-400 transition-colors"
              >
                <LogOut className="w-4 h-4" />
              </button>
            </div>
          ) : (
            <button
              type="button"
              onClick={onOpenLogin}
              className="bg-blue-600 hover:bg-blue-500 text-white font-semibold px-4 py-1.5 rounded-lg text-xs transition-colors shadow-sm"
            >
              Sign In
            </button>
          )}
        </div>

      </div>

      {/* Mobile Menu Dropdown matching Screenshot 1/5 EasyDMARC/PowerDMARC style */}
      {mobileMenuOpen && (
        <div className="md:hidden bg-white text-slate-900 border-b border-slate-200 shadow-xl px-4 py-4 space-y-3 font-sans">
          <div className="text-[11px] font-bold text-slate-400 uppercase tracking-wider px-2">
            Phishing Detection System
          </div>
          <div className="space-y-1">
            <a
              href="#checker"
              onClick={() => setMobileMenuOpen(false)}
              className="flex items-center justify-between px-3 py-2 text-sm text-slate-700 hover:bg-slate-50 rounded-lg font-medium"
            >
              <span>Phishing Link Checker</span>
              <ChevronRight className="w-4 h-4 text-slate-400" />
            </a>
            <a
              href="#recent"
              onClick={() => setMobileMenuOpen(false)}
              className="flex items-center justify-between px-3 py-2 text-sm text-slate-700 hover:bg-slate-50 rounded-lg font-medium"
            >
              <span>Recent Scans</span>
              <ChevronRight className="w-4 h-4 text-slate-400" />
            </a>
            <a
              href="#about"
              onClick={() => setMobileMenuOpen(false)}
              className="flex items-center justify-between px-3 py-2 text-sm text-slate-700 hover:bg-slate-50 rounded-lg font-medium"
            >
              <span>Threat Intelligence Engine</span>
              <ChevronRight className="w-4 h-4 text-slate-400" />
            </a>
          </div>

          <div className="pt-3 border-t border-slate-100 flex items-center justify-between">
            {user ? (
              <div className="flex items-center justify-between w-full">
                <span className="text-xs text-slate-600">Logged in as <strong>{user.email}</strong></span>
                <button
                  onClick={() => { onLogout(); setMobileMenuOpen(false); }}
                  className="text-xs text-red-600 font-semibold"
                >
                  Sign Out
                </button>
              </div>
            ) : (
              <button
                onClick={() => { onOpenLogin(); setMobileMenuOpen(false); }}
                className="w-full bg-blue-600 text-white py-2 rounded-lg text-xs font-semibold text-center"
              >
                Sign In / Create Account
              </button>
            )}
          </div>
        </div>
      )}
    </header>
  );
};
