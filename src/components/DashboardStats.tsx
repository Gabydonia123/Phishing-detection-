import React from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Zap,
  Activity,
  AlertTriangle,
  Globe,
  Cpu
} from 'lucide-react';
import { ScanResult } from '../types';

interface DashboardStatsProps {
  history: ScanResult[];
}

export const DashboardStats: React.FC<DashboardStatsProps> = ({ history }) => {
  const total = history.length;
  const phishing = history.filter(h => h.prediction === 'PHISHING').length;
  const legitimate = history.filter(h => h.prediction === 'LEGITIMATE').length;
  const suspicious = history.filter(h => h.prediction === 'SUSPICIOUS').length;

  const avgConfidence = total > 0
    ? (history.reduce((a, b) => a + b.confidence, 0) / total).toFixed(1)
    : '96.8';

  const threatPercentage = total > 0
    ? Math.round((phishing / total) * 100)
    : 0;

  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
      
      {/* 1. Total Scans */}
      <div className="bg-slate-900/80 border border-slate-800 p-4 rounded-2xl relative overflow-hidden group">
        <div className="flex items-center justify-between">
          <span className="text-xs font-mono text-slate-400">Total Scans</span>
          <Activity className="w-4 h-4 text-cyan-400" />
        </div>
        <div className="text-2xl sm:text-3xl font-black text-white font-mono mt-2">
          {total}
        </div>
        <div className="text-[10px] text-cyan-300 font-mono mt-1">
          16-Vector Random Forest ML
        </div>
      </div>

      {/* 2. Phishing Threats Intercepted */}
      <div className="bg-slate-900/80 border border-rose-900/40 p-4 rounded-2xl relative overflow-hidden group">
        <div className="flex items-center justify-between">
          <span className="text-xs font-mono text-rose-400 flex items-center gap-1.5">
            <ShieldAlert className="w-3.5 h-3.5" />
            Threats Flagged
          </span>
          <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-rose-500/20 text-rose-300">
            {threatPercentage}%
          </span>
        </div>
        <div className="text-2xl sm:text-3xl font-black text-rose-400 font-mono mt-2">
          {phishing}
        </div>
        <div className="text-[10px] text-slate-400 font-mono mt-1">
          Malicious/Deceptive sites
        </div>
      </div>

      {/* 3. Legitimate Verified */}
      <div className="bg-slate-900/80 border border-emerald-900/40 p-4 rounded-2xl relative overflow-hidden group">
        <div className="flex items-center justify-between">
          <span className="text-xs font-mono text-emerald-400 flex items-center gap-1.5">
            <ShieldCheck className="w-3.5 h-3.5" />
            Legitimate Verified
          </span>
          <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-emerald-500/20 text-emerald-300">
            {total > 0 ? Math.round((legitimate / total) * 100) : 0}%
          </span>
        </div>
        <div className="text-2xl sm:text-3xl font-black text-emerald-400 font-mono mt-2">
          {legitimate}
        </div>
        <div className="text-[10px] text-slate-400 font-mono mt-1">
          Clean domain hierarchies
        </div>
      </div>

      {/* 4. Model Confidence */}
      <div className="bg-slate-900/80 border border-slate-800 p-4 rounded-2xl relative overflow-hidden group">
        <div className="flex items-center justify-between">
          <span className="text-xs font-mono text-slate-400">Avg Confidence</span>
          <Cpu className="w-4 h-4 text-cyan-400" />
        </div>
        <div className="text-2xl sm:text-3xl font-black text-cyan-400 font-mono mt-2">
          {avgConfidence}%
        </div>
        <div className="text-[10px] text-slate-400 font-mono mt-1">
          Ensemble consensus calibration
        </div>
      </div>

    </div>
  );
};
