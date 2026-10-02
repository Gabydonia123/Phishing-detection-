import React, { useState } from 'react';
import {
  History,
  Trash2,
  Download,
  Search,
  ExternalLink,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Clock,
  Filter,
  FileSpreadsheet,
  FileText
} from 'lucide-react';
import { ScanResult } from '../types';

interface ScanHistoryProps {
  history: ScanResult[];
  onClearHistory: () => void;
  onSelectUrlForInspect: (url: string) => void;
}

export const ScanHistory: React.FC<ScanHistoryProps> = ({
  history,
  onClearHistory,
  onSelectUrlForInspect
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterVerdict, setFilterVerdict] = useState<string>('ALL');

  const filtered = history.filter((item) => {
    const matchesSearch = item.canonicalUrl.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          item.domain.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesFilter = filterVerdict === 'ALL' || item.prediction === filterVerdict;
    return matchesSearch && matchesFilter;
  });

  const exportCSV = () => {
    if (history.length === 0) return;
    const headers = ['URL', 'Domain', 'Verdict', 'Confidence %', 'Risk Score', 'Entropy', 'Timestamp'];
    const rows = history.map(r => [
      `"${r.canonicalUrl}"`,
      `"${r.domain}"`,
      r.prediction,
      r.confidence,
      r.riskScore,
      r.entropyScore,
      `"${r.timestamp}"`
    ]);

    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `PhishGuard_Scan_History_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="space-y-6">
      
      {/* Header */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <History className="w-4 h-4 text-cyan-400" />
              <span className="text-xs uppercase tracking-wider text-cyan-400 font-mono font-semibold">
                Audit Log & Incident Records
              </span>
            </div>
            <h2 className="text-xl sm:text-2xl font-bold text-white mt-1">
              Phishing Scan Forensic History
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Review, filter, re-inspect, and export previously executed Random Forest security evaluations.
            </p>
          </div>

          <div className="flex items-center gap-2">
            {history.length > 0 && (
              <>
                <button
                  type="button"
                  onClick={exportCSV}
                  className="px-3 py-1.5 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded-lg text-xs font-mono text-slate-300 hover:text-white transition-colors flex items-center gap-1.5"
                >
                  <Download className="w-3.5 h-3.5 text-cyan-400" />
                  Export History
                </button>
                <button
                  type="button"
                  onClick={onClearHistory}
                  className="px-3 py-1.5 bg-rose-950/40 hover:bg-rose-900/60 border border-rose-800/60 rounded-lg text-xs font-mono text-rose-300 transition-colors flex items-center gap-1.5"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  Clear
                </button>
              </>
            )}
          </div>
        </div>

        {/* Filter Controls */}
        <div className="mt-5 pt-4 border-t border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="relative flex-1 max-w-md">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5 pointer-events-none" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Filter by URL or target domain..."
              className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-white placeholder-slate-400 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>

          <div className="flex bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs">
            {['ALL', 'PHISHING', 'LEGITIMATE', 'SUSPICIOUS'].map(cat => (
              <button
                key={cat}
                onClick={() => setFilterVerdict(cat)}
                className={`px-3 py-1 rounded font-mono ${
                  filterVerdict === cat ? 'bg-cyan-500 text-slate-950 font-bold' : 'text-slate-400 hover:text-white'
                }`}
              >
                {cat}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* History Table or Empty State */}
      {filtered.length === 0 ? (
        <div className="bg-slate-900/50 border border-slate-800 rounded-2xl p-12 text-center">
          <History className="w-12 h-12 text-slate-600 mx-auto mb-3" />
          <h3 className="text-base font-bold text-white font-mono">No Scan Records Found</h3>
          <p className="text-xs text-slate-400 mt-1 max-w-sm mx-auto">
            {history.length === 0
              ? 'Execute website analyses in the URL Scanner or Batch Scanner to log detection forensics.'
              : 'No scans matched your search query.'}
          </p>
        </div>
      ) : (
        <div className="bg-slate-900/90 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-950 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">Verdict</th>
                  <th className="py-3 px-4">URL / Domain</th>
                  <th className="py-3 px-4">Confidence</th>
                  <th className="py-3 px-4">Risk</th>
                  <th className="py-3 px-4">Ensemble Votes</th>
                  <th className="py-3 px-4">Scanned At</th>
                  <th className="py-3 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filtered.map((item) => {
                  const isPhish = item.prediction === 'PHISHING';
                  const isSusp = item.prediction === 'SUSPICIOUS';
                  return (
                    <tr key={item.id} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-3.5 px-4">
                        <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-bold border ${
                          isPhish
                            ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                            : isSusp
                            ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                            : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                        }`}>
                          {isPhish ? <ShieldAlert className="w-3 h-3" /> : isSusp ? <AlertTriangle className="w-3 h-3" /> : <ShieldCheck className="w-3 h-3" />}
                          {item.prediction}
                        </span>
                      </td>
                      <td className="py-3.5 px-4 max-w-[280px]">
                        <div className="text-white font-medium truncate" title={item.canonicalUrl}>
                          {item.canonicalUrl}
                        </div>
                        <div className="text-[10px] text-slate-400 truncate">
                          {item.domain} • Shannon: {item.entropyScore}
                        </div>
                      </td>
                      <td className="py-3.5 px-4 font-bold text-slate-200">
                        {item.confidence}%
                      </td>
                      <td className="py-3.5 px-4">
                        <span className={`font-bold ${item.riskScore > 60 ? 'text-rose-400' : item.riskScore > 35 ? 'text-amber-400' : 'text-emerald-400'}`}>
                          {item.riskScore}/100
                        </span>
                      </td>
                      <td className="py-3.5 px-4 text-slate-300">
                        <span className="text-rose-400 font-bold">{item.treesPhishingVotes}</span> / {item.totalTrees} Phish
                      </td>
                      <td className="py-3.5 px-4 text-slate-400 text-[11px]">
                        {new Date(item.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                      </td>
                      <td className="py-3.5 px-4 text-right">
                        <button
                          type="button"
                          onClick={() => onSelectUrlForInspect(item.url)}
                          className="px-2.5 py-1 bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 rounded text-[10px] transition-colors inline-flex items-center gap-1"
                        >
                          <span>Re-Inspect</span>
                          <ExternalLink className="w-2.5 h-2.5" />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

    </div>
  );
};
