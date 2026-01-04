import { Card } from "./Card";
import { AlertCircle, ShieldAlert, CheckCircle } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

interface Alert {
    id: string | number;
    type: string;
    classification: string;
    confidence: number;
    timestamp: string;
    source_ip: string;
    details?: string;
}

export function AlertFeed({ alerts }: { alerts: Alert[] }) {
    return (
        <Card className="h-[400px] flex flex-col bg-slate-800/80 border-slate-700">
            <div className="flex justify-between items-center mb-4 px-1">
                <h3 className="text-lg font-bold text-white flex items-center gap-2">
                    <ShieldAlert className="text-rose-500" />
                    Live Threat Feed
                </h3>
                <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-rose-500/10 text-rose-400 text-xs font-medium border border-rose-500/20">
                    <span className="w-1.5 h-1.5 rounded-full bg-rose-500 animate-pulse"></span>
                    Live Stream
                </span>
            </div>

            <div className="overflow-y-auto space-y-2 pr-2 scrollbar-thin scrollbar-thumb-slate-700">
                <AnimatePresence initial={false}>
                    {alerts.length === 0 ? (
                        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="text-center py-12 text-slate-500">
                            <CheckCircle className="mx-auto mb-3 opacity-20" size={40} />
                            <p className="text-sm">No active threats detected</p>
                        </motion.div>
                    ) : (
                        alerts.map((alert) => (
                            <motion.div
                                key={alert.id}
                                initial={{ opacity: 0, x: -10 }}
                                animate={{ opacity: 1, x: 0 }}
                                exit={{ opacity: 0, height: 0 }}
                                className="p-3.5 rounded-lg bg-slate-700/30 border border-slate-700/50 hover:bg-slate-700/50 transition-all cursor-default group"
                            >
                                <div className="flex justify-between items-start mb-2">
                                    <div className="flex items-center gap-2">
                                        <span className="font-semibold text-rose-200 group-hover:text-white transition-colors text-sm">
                                            {alert.classification}
                                        </span>
                                        {/* MIXED DETECTION TAGS */}
                                        {alert.details && alert.details.includes("YARA") ? (
                                            <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                                                SIG
                                            </span>
                                        ) : (
                                            <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-purple-500/20 text-purple-300 border border-purple-500/30">
                                                AI
                                            </span>
                                        )}
                                    </div>
                                    <span className="text-xs text-slate-500 font-mono">
                                        {new Date(alert.timestamp).toLocaleTimeString()}
                                    </span>
                                </div>
                                <div className="flex justify-between items-end">
                                    <div className="text-xs text-slate-400 space-y-0.5">
                                        <div className="flex items-center gap-1.5">
                                            <span className="uppercase text-[10px] font-semibold tracking-wider text-slate-500">TYPE:</span>
                                            {alert.type}
                                        </div>
                                        <div className="flex items-center gap-1.5">
                                            <span className="uppercase text-[10px] font-semibold tracking-wider text-slate-500">SRC:</span>
                                            <span className="font-mono text-slate-300">{alert.source_ip}</span>
                                        </div>
                                    </div>
                                    <div className="px-2 py-1 rounded bg-slate-800 text-rose-400 text-xs font-bold border border-slate-600">
                                        {(alert.confidence * 100).toFixed(0)}%
                                    </div>
                                </div>
                            </motion.div>
                        ))
                    )}
                </AnimatePresence>
            </div>
        </Card>
    );
}
