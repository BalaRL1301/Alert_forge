"use client";

import { useState } from "react";
import { Sidebar } from "@/components/Sidebar";
import { Zap, Terminal, ShieldAlert, Lock, Database } from "lucide-react";
import { motion } from "framer-motion";

const API_URL = "http://localhost:8000";

export default function AttackSimulator() {
    const [logs, setLogs] = useState<string[]>([]);
    const [attacking, setAttacking] = useState(false);

    const launchAttack = async (type: string, name: string) => {
        setAttacking(true);
        setLogs(prev => [...prev, `[INIT] Initializing ${name} module...`]);
        setLogs(prev => [...prev, `[INFO] Targeting ${API_URL.replace('8000', '5001')}...`]);

        try {
            const res = await fetch(`${API_URL}/simulate/attack?type=${type}`, { method: 'POST' });
            const data = await res.json();

            if (data.status === "completed") {
                setLogs(prev => [...prev, ...data.logs]);
                setLogs(prev => [...prev, `[SUCCESS] ${name} execution completed.`]);
            } else {
                setLogs(prev => [...prev, `[ERROR] Attack failed: ${data.message}`]);
            }
        } catch (e) {
            setLogs(prev => [...prev, `[CRITICAL] Connection refused or timeout.`]);
        }
        setAttacking(false);
    };

    return (
        <div className="flex h-screen overflow-hidden bg-slate-950 text-slate-100">
            <Sidebar />

            <main className="flex-1 overflow-y-auto p-8 flex flex-col">
                <header className="mb-8">
                    <h1 className="text-3xl font-bold text-white mb-2 flex items-center gap-3">
                        <Zap className="text-amber-500" size={32} />
                        Red Team Simulator
                    </h1>
                    <p className="text-slate-400">Launch controlled cyber-attacks to validate defense mechanisms.</p>
                </header>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 flex-1 min-h-0">
                    {/* Attack Control Panel */}
                    <div className="space-y-6">
                        <div className="grid grid-cols-1 gap-4">
                            <AttackCard
                                name="SQL Injection Storm"
                                desc="Injects malicious SQL payloads to bypass authentication."
                                type="sqli"
                                icon={<Database />}
                                color="bg-rose-600"
                                onClick={() => launchAttack("sqli", "SQL Injection")}
                                disabled={attacking}
                            />
                            <AttackCard
                                name="XSS Payload Spray"
                                desc="Injects polyglot JavaScript vectors into inputs."
                                type="xss"
                                icon={<ShieldAlert />}
                                color="bg-orange-600"
                                onClick={() => launchAttack("xss", "XSS Spray")}
                                disabled={attacking}
                            />
                            <AttackCard
                                name="Credential Brute Force"
                                desc="Attempts dictionary attacks against login endpoints."
                                type="brute"
                                icon={<Lock />}
                                color="bg-red-600"
                                onClick={() => launchAttack("brute", "Brute Force")}
                                disabled={attacking}
                            />
                        </div>

                        <div className="bg-slate-900/50 p-6 rounded-xl border border-dashed border-slate-700 text-center">
                            <p className="text-sm text-slate-500 mb-2">Warning: These attacks are routed internally.</p>
                            <p className="text-xs text-slate-600">Do not run against external targets.</p>
                        </div>
                    </div>

                    {/* Console Output */}
                    <div className="bg-black rounded-xl border border-slate-800 flex flex-col overflow-hidden shadow-2xl">
                        <div className="bg-slate-900 p-3 border-b border-slate-800 flex items-center gap-2">
                            <Terminal size={16} className="text-slate-400" />
                            <span className="text-xs font-mono font-bold text-slate-300">ATTACK_CONSOLE // OUTPUT</span>
                        </div>
                        <div className="flex-1 p-4 font-mono text-xs overflow-y-auto space-y-1">
                            {logs.length === 0 && <span className="text-slate-600">Waiting for command...</span>}
                            {logs.map((log, i) => (
                                <div key={i} className={`${log.includes('ERROR') ? 'text-red-400' : 'text-green-400'}`}>
                                    {log}
                                </div>
                            ))}
                            {attacking && (
                                <div className="text-amber-500 animate-pulse">_ EXECUTION IN PROGRESS...</div>
                            )}
                        </div>
                    </div>
                </div>

            </main>
        </div>
    );
}

function AttackCard({ name, desc, type, icon, color, onClick, disabled }: any) {
    return (
        <button
            onClick={onClick}
            disabled={disabled}
            className="group relative overflow-hidden bg-slate-900 border border-slate-800 p-6 rounded-xl text-left hover:border-slate-600 transition-all active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed"
        >
            <div className={`absolute top-0 right-0 p-2 rounded-bl-xl ${color} text-white opacity-20 group-hover:opacity-100 transition-all`}>
                <Zap size={20} />
            </div>
            <div className="flex items-start gap-4">
                <div className={`p-3 rounded-lg bg-slate-800 ${disabled ? 'text-slate-500' : 'text-slate-200 group-hover:text-white'}`}>
                    {icon}
                </div>
                <div>
                    <h3 className="text-lg font-bold text-white mb-1">{name}</h3>
                    <p className="text-sm text-slate-400">{desc}</p>
                </div>
            </div>
        </button>
    );
}
