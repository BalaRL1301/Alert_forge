'use client';

import { useState, useEffect, useRef } from 'react';
import { Sidebar } from "@/components/Sidebar";
import { LiveTrafficChart } from "@/components/LiveTrafficChart";
import { Card } from "@/components/Card";
import { Shield, Zap, Terminal, Globe, Filter } from "lucide-react";
import { motion } from "framer-motion";

const API_URL = 'http://localhost:8000';

export default function LiveMonitoring() {
    const [logs, setLogs] = useState([]);
    const [chartData, setChartData] = useState<any[]>([]);
    const [autoScroll, setAutoScroll] = useState(true);
    const logEndRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        const fetchData = async () => {
            try {
                const logsRes = await fetch(`${API_URL}/logs?limit=100`);
                const logsData = await logsRes.json();
                setLogs(logsData);

                // Chart Data Simulation (smoothed)
                setChartData(prev => {
                    const now = new Date();
                    const timeStr = now.toLocaleTimeString('en-US', { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
                    const newVal = { time: timeStr, value: Math.floor(Math.random() * 50) + 10 };
                    const newData = [...prev, newVal];
                    if (newData.length > 30) newData.shift();
                    return newData;
                });

            } catch (e) {
                console.error("API connection failed", e);
            }
        };

        fetchData();
        const interval = setInterval(fetchData, 1000); // Fast polling (1s)
        return () => clearInterval(interval);
    }, []);

    // Auto-scroll logs
    useEffect(() => {
        if (autoScroll && logEndRef.current) {
            logEndRef.current.scrollIntoView({ behavior: 'smooth' });
        }
    }, [logs, autoScroll]);

    return (
        <div className="flex h-screen overflow-hidden bg-slate-950 text-slate-100">
            <Sidebar />

            <main className="flex-1 overflow-y-auto p-0 relative flex flex-col">
                {/* Header Bar */}
                <header className="bg-slate-900 border-b border-slate-800 p-4 flex justify-between items-center z-20 shadow-md">
                    <div>
                        <h1 className="text-xl font-bold text-white flex items-center gap-2">
                            <ActivityIcon />
                            Live Operations Center
                        </h1>
                        <p className="text-xs text-slate-400">Real-time telemetry and threat interception.</p>
                    </div>
                    <div className="flex items-center gap-4">
                        <div className="flex items-center gap-2 text-xs font-mono text-emerald-400">
                            <span className="relative flex h-2 w-2">
                                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                            </span>
                            LIVE FEED ACTIVE
                        </div>
                    </div>
                </header>

                <div className="flex-1 p-6 grid grid-cols-1 lg:grid-cols-3 gap-6 overflow-hidden">

                    {/* LEFT COLUMN: Visuals */}
                    <div className="lg:col-span-2 flex flex-col gap-6 overflow-y-auto pr-2">
                        {/* Traffic Chart */}
                        <Card className="bg-slate-900/50 border-slate-800 p-0 overflow-hidden">
                            <div className="p-4 border-b border-slate-800 flex justify-between items-center">
                                <h3 className="font-semibold text-slate-200">Network Traffic Ingress</h3>
                                <select className="bg-slate-800 border-slate-700 text-xs rounded px-2 py-1">
                                    <option>Last 30 Seconds</option>
                                    <option>Last 5 Minutes</option>
                                </select>
                            </div>
                            <div className="p-4">
                                <LiveTrafficChart data={chartData} height={250} />
                            </div>
                        </Card>

                        {/* Geo Map Placeholder */}
                        <div className="grid grid-cols-2 gap-6">
                            <Card className="bg-slate-900/50 border-slate-800 min-h-[200px] flex flex-col">
                                <div className="p-4 border-b border-slate-800 flex items-center gap-2">
                                    <Globe size={16} className="text-blue-400" />
                                    <h3 className="font-semibold text-slate-200">Threat Origins</h3>
                                </div>
                                <div className="flex-1 flex items-center justify-center relative overflow-hidden">
                                    {/* Abstract Map Dots */}
                                    <div className="absolute inset-0 opacity-20 bg-[url('/globe.svg')] bg-no-repeat bg-center bg-contain"></div>
                                    <div className="z-10 text-center">
                                        <div className="text-4xl font-bold text-white">124</div>
                                        <div className="text-xs text-slate-400">Active Sources</div>
                                    </div>
                                </div>
                            </Card>

                            <Card className="bg-slate-900/50 border-slate-800 min-h-[200px] flex flex-col">
                                <div className="p-4 border-b border-slate-800 flex items-center gap-2">
                                    <Zap size={16} className="text-amber-400" />
                                    <h3 className="font-semibold text-slate-200">Attack Types</h3>
                                </div>
                                <div className="flex-1 p-4 space-y-3">
                                    <AttackBar label="SQL Injection" count={45} total={100} color="bg-rose-500" />
                                    <AttackBar label="XSS" count={28} total={100} color="bg-orange-500" />
                                    <AttackBar label="Brute Force" count={12} total={100} color="bg-yellow-500" />
                                    <AttackBar label="Port Scan" count={8} total={100} color="bg-blue-500" />
                                </div>
                            </Card>
                        </div>
                    </div>

                    {/* RIGHT COLUMN: Terminal Log */}
                    <div className="lg:col-span-1 flex flex-col h-full min-h-[500px]">
                        <Card className="flex-1 bg-black border-slate-800 flex flex-col overflow-hidden shadow-2xl">
                            <div className="p-3 bg-slate-900 border-b border-slate-800 flex justify-between items-center">
                                <div className="flex items-center gap-2 text-slate-300">
                                    <Terminal size={16} />
                                    <span className="font-mono text-xs font-bold">STREAM_V1.log</span>
                                </div>
                                <button
                                    onClick={() => setAutoScroll(!autoScroll)}
                                    className={`text-xs px-2 py-1 rounded ${autoScroll ? 'bg-blue-500/20 text-blue-400' : 'bg-slate-800 text-slate-400'}`}
                                >
                                    {autoScroll ? 'SCROLL: ON' : 'PAUSED'}
                                </button>
                            </div>
                            <div className="flex-1 overflow-y-auto p-4 font-mono text-xs space-y-2 scrollbar-thin scrollbar-thumb-slate-700">
                                {[...logs].reverse().map((log: any, i) => (
                                    <div key={i} className="flex gap-2 animate-in fade-in slide-in-from-left-2 duration-100">
                                        <span className="text-slate-500 shrink-0">[{new Date(log.timestamp).toLocaleTimeString()}]</span>
                                        {log.analysis.is_threat ? (
                                            <span className="text-rose-400 font-bold shrink-0">BLOCK</span>
                                        ) : (
                                            <span className="text-emerald-500 shrink-0">PASS</span>
                                        )}
                                        <span className="text-slate-300 break-all">
                                            {log.source_ip} - {log.message || log.raw_message}
                                        </span>
                                    </div>
                                ))}
                                <div ref={logEndRef} />
                            </div>
                        </Card>
                    </div>

                </div>
            </main>
        </div>
    );
}

function AttackBar({ label, count, total, color }: { label: string, count: number, total: number, color: string }) {
    const width = `${(count / total) * 100}%`;
    return (
        <div>
            <div className="flex justify-between text-xs mb-1">
                <span className="text-slate-300">{label}</span>
                <span className="text-slate-400">{count}</span>
            </div>
            <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                <div style={{ width }} className={`h-full ${color} rounded-full`} />
            </div>
        </div>
    );
}

function ActivityIcon() {
    return (
        <svg className="w-5 h-5 text-primary" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline>
        </svg>
    );
}
