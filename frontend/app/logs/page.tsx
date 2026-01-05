"use client";

import { useState, useEffect } from "react";
import { Sidebar } from "@/components/Sidebar";
import { Download, Search, Filter, AlertTriangle, CheckCircle, ChevronDown, ChevronRight, X, Zap } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

const API_URL = "http://localhost:8000";

export default function LogsExplorer() {
    const [logs, setLogs] = useState([]);
    const [loading, setLoading] = useState(true);
    const [searchTerm, setSearchTerm] = useState("");
    const [filterType, setFilterType] = useState<"all" | "threat" | "clean">("all");
    const [selectedLog, setSelectedLog] = useState<any>(null);

    useEffect(() => {
        const fetchLogs = async () => {
            try {
                const res = await fetch(`${API_URL}/logs?limit=200`);
                const data = await res.json();
                setLogs(data);
                setLoading(false);
            } catch (err) {
                console.error("Failed to fetch logs", err);
                setLoading(false);
            }
        };

        fetchLogs();
        const interval = setInterval(fetchLogs, 5000);
        return () => clearInterval(interval);
    }, []);

    // Filtering Logic
    const filteredLogs = logs.filter((log: any) => {
        const matchesSearch =
            log.source_ip.includes(searchTerm) ||
            (log.message || log.raw_message)?.toLowerCase().includes(searchTerm.toLowerCase());

        const matchesType =
            filterType === "all" ? true :
                filterType === "threat" ? log.analysis.is_threat :
                    !log.analysis.is_threat;

        return matchesSearch && matchesType;
    });

    const handleExport = () => {
        const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(filteredLogs, null, 2));
        const downloadAnchorNode = document.createElement('a');
        downloadAnchorNode.setAttribute("href", dataStr);
        downloadAnchorNode.setAttribute("download", `alertforge_logs_${new Date().toISOString()}.json`);
        document.body.appendChild(downloadAnchorNode);
        downloadAnchorNode.click();
        downloadAnchorNode.remove();
    };

    return (
        <div className="flex h-screen overflow-hidden bg-slate-950 text-slate-100">
            <Sidebar />

            <main className="flex-1 overflow-y-auto p-8 relative flex flex-col">
                <header className="mb-8 flex flex-col md:flex-row md:items-center justify-between gap-4">
                    <div>
                        <h1 className="text-3xl font-bold text-white mb-2">Logs Explorer</h1>
                        <p className="text-slate-400">Deep dive into system telemetry and security events.</p>
                    </div>
                    <div className="flex items-center gap-3">
                        <button
                            onClick={handleExport}
                            className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg border border-slate-700 transition-colors text-sm font-medium"
                        >
                            <Download size={16} /> Export JSON
                        </button>
                    </div>
                </header>

                {/* Controls */}
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 mb-6 flex flex-col md:flex-row gap-4">
                    <div className="relative flex-1">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" size={18} />
                        <input
                            type="text"
                            placeholder="Search IP, payload, or details..."
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                            className="w-full bg-slate-800 border border-slate-700 text-white pl-10 pr-4 py-2 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 placeholder:text-slate-500"
                        />
                    </div>
                    <div className="flex items-center gap-2 bg-slate-800 rounded-lg p-1 border border-slate-700">
                        <FilterBtn label="All Events" active={filterType === "all"} onClick={() => setFilterType("all")} />
                        <FilterBtn label="Threats Only" active={filterType === "threat"} onClick={() => setFilterType("threat")} icon={<AlertTriangle size={14} />} />
                        <FilterBtn label="Clean Traffic" active={filterType === "clean"} onClick={() => setFilterType("clean")} icon={<CheckCircle size={14} />} />
                    </div>
                </div>

                {/* Data Grid */}
                <div className="flex-1 bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg flex flex-col">
                    <div className="overflow-x-auto flex-1">
                        <table className="w-full text-left text-sm text-slate-400">
                            <thead className="bg-slate-950 uppercase font-semibold text-xs tracking-wider border-b border-slate-800">
                                <tr>
                                    <th className="px-6 py-4 w-48">Timestamp</th>
                                    <th className="px-6 py-4 w-40">Source IP</th>
                                    <th className="px-6 py-4 w-32">Status</th>
                                    <th className="px-6 py-4">Event Payload</th>
                                    <th className="px-6 py-4 w-24">Confidence</th>
                                    <th className="px-6 py-4 w-10"></th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-800">
                                {loading ? (
                                    <tr><td colSpan={6} className="p-8 text-center text-slate-500">Loading logs...</td></tr>
                                ) : filteredLogs.length === 0 ? (
                                    <tr><td colSpan={6} className="p-8 text-center text-slate-500">No logs found matching your criteria.</td></tr>
                                ) : (
                                    filteredLogs.map((log: any, i) => (
                                        <tr
                                            key={i}
                                            onClick={() => setSelectedLog(log)}
                                            className="hover:bg-slate-800/50 cursor-pointer transition-colors group"
                                        >
                                            <td className="px-6 py-3 font-mono text-xs text-slate-500">
                                                {new Date(log.timestamp).toLocaleString()}
                                            </td>
                                            <td className="px-6 py-3 font-mono text-xs text-slate-300">
                                                {log.source_ip}
                                            </td>
                                            <td className="px-6 py-3">
                                                {log.analysis.is_threat ? (
                                                    <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/10 text-rose-400 border border-rose-500/20 uppercase tracking-wide">
                                                        Threat
                                                    </span>
                                                ) : (
                                                    <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 uppercase tracking-wide">
                                                        Clean
                                                    </span>
                                                )}
                                            </td>
                                            <td className="px-6 py-3 max-w-sm truncate text-slate-300 group-hover:text-white">
                                                {log.message || log.raw_message}
                                            </td>
                                            <td className="px-6 py-3">
                                                {log.analysis.confidence > 0 && (
                                                    <div className="flex items-center gap-2">
                                                        <div className="w-16 h-1 bg-slate-700 rounded-full overflow-hidden">
                                                            <div
                                                                className={`h-full rounded-full ${log.analysis.confidence > 0.8 ? 'bg-rose-500' : 'bg-amber-500'}`}
                                                                style={{ width: `${log.analysis.confidence * 100}%` }}
                                                            />
                                                        </div>
                                                        <span className="text-xs font-mono">{Math.round(log.analysis.confidence * 100)}%</span>
                                                    </div>
                                                )}
                                            </td>
                                            <td className="px-6 py-3 text-right">
                                                <ChevronRight size={16} className="text-slate-600 group-hover:text-white" />
                                            </td>
                                        </tr>
                                    ))
                                )}
                            </tbody>
                        </table>
                    </div>
                    <div className="bg-slate-950 p-3 border-t border-slate-800 text-xs text-slate-500 flex justify-between items-center">
                        <div>Showing {filteredLogs.length} events</div>
                        <div>Auto-refreshing every 5s</div>
                    </div>
                </div>

            </main>

            {/* Detail Modal */}
            <AnimatePresence>
                {selectedLog && (
                    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4">
                        <motion.div
                            initial={{ opacity: 0, scale: 0.95 }}
                            animate={{ opacity: 1, scale: 1 }}
                            exit={{ opacity: 0, scale: 0.95 }}
                            className="bg-slate-900 border border-slate-700 w-full max-w-3xl max-h-[85vh] rounded-2xl shadow-2xl overflow-hidden flex flex-col"
                        >
                            <div className="p-6 border-b border-slate-800 flex justify-between items-start">
                                <div>
                                    <div className="flex items-center gap-3 mb-1">
                                        {selectedLog.analysis.is_threat ? (
                                            <span className="px-2 py-1 bg-rose-500 text-white text-xs font-bold rounded">THREAT DETECTED</span>
                                        ) : (
                                            <span className="px-2 py-1 bg-emerald-500 text-white text-xs font-bold rounded">CLEAN TRAFFIC</span>
                                        )}
                                        <h2 className="text-xl font-bold text-white font-mono">{selectedLog.source_ip}</h2>
                                    </div>
                                    <p className="text-slate-400 text-sm">{new Date(selectedLog.timestamp).toUTCString()}</p>
                                </div>
                                <button onClick={() => setSelectedLog(null)} className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800">
                                    <X size={24} />
                                </button>
                            </div>

                            <div className="flex-1 overflow-y-auto p-6 space-y-6">
                                {/* Analysis Section */}
                                <div className="space-y-4">
                                    <h3 className="text-sm font-bold text-slate-200 uppercase tracking-widest border-b border-slate-800 pb-2">Analysis Engine</h3>

                                    <div className="grid grid-cols-2 lg:grid-cols-3 gap-4">
                                        <DetailCard label="Classification" value={selectedLog.analysis.classification} />
                                        <DetailCard label="Detection Type" value={selectedLog.analysis.type} />
                                        <DetailCard label="Confidence Score" value={(selectedLog.analysis.confidence * 100).toFixed(1) + '%'} highlight={selectedLog.analysis.is_threat} />
                                    </div>

                                    {selectedLog.analysis.details && (
                                        <div className="bg-slate-950 rounded-lg p-4 border border-slate-800">
                                            <div className="text-xs text-slate-500 mb-2 font-mono">ENGINE OUTPUT</div>
                                            <p className="text-slate-300 font-mono text-sm whitespace-pre-wrap">{selectedLog.analysis.details}</p>
                                        </div>
                                    )}

                                    {/* AI Analysis Report */}
                                    {selectedLog.ai_analysis && (
                                        <div className="bg-slate-900 border border-indigo-500/30 rounded-lg p-6 relative overflow-hidden group">
                                            <div className="absolute top-0 left-0 w-1 h-full bg-indigo-500"></div>
                                            <div className="flex items-center gap-2 mb-3">
                                                <div className="p-1.5 rounded bg-indigo-500/10 text-indigo-400">
                                                    <Zap size={16} />
                                                </div>
                                                <h3 className="font-bold text-indigo-100">AI Security Analyst Report</h3>
                                            </div>
                                            <p className="text-slate-300 text-sm leading-relaxed whitespace-pre-wrap">
                                                {selectedLog.ai_analysis}
                                            </p>
                                        </div>
                                    )}
                                </div>

                                {/* Raw Data Section */}
                                <div className="space-y-4">
                                    <h3 className="text-sm font-bold text-slate-200 uppercase tracking-widest border-b border-slate-800 pb-2">Raw Payload</h3>
                                    <div className="bg-black rounded-lg p-4 border border-slate-800 font-mono text-xs text-blue-300 overflow-x-auto">
                                        <pre>{JSON.stringify(selectedLog, null, 2)}</pre>
                                    </div>
                                </div>
                            </div>

                            <div className="p-4 border-t border-slate-800 bg-slate-950 flex justify-end gap-3">
                                <button onClick={() => setSelectedLog(null)} className="px-4 py-2 text-slate-300 hover:text-white transition-colors text-sm font-medium">
                                    Close
                                </button>
                            </div>
                        </motion.div>
                        {/* Click backdrop to close */}
                        <div className="absolute inset-0 -z-10" onClick={() => setSelectedLog(null)} />
                    </div>
                )}
            </AnimatePresence>
        </div>
    );
}

function FilterBtn({ label, active, onClick, icon }: { label: string, active: boolean, onClick: () => void, icon?: React.ReactNode }) {
    return (
        <button
            onClick={onClick}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-semibold transition-all ${active
                ? "bg-blue-600 text-white shadow-lg shadow-blue-500/20"
                : "text-slate-400 hover:text-white hover:bg-slate-700"
                }`}
        >
            {icon} {label}
        </button>
    );
}

function DetailCard({ label, value, highlight = false }: { label: string, value: string, highlight?: boolean }) {
    return (
        <div className="bg-slate-800/50 p-3 rounded-lg border border-slate-700/50">
            <div className="text-xs text-slate-500 mb-1">{label}</div>
            <div className={`font-semibold ${highlight ? 'text-rose-400' : 'text-slate-200'}`}>{value}</div>
        </div>
    );
}
