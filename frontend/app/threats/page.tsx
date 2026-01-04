"use client";

import { useState, useEffect } from "react";
import { Sidebar } from "@/components/Sidebar";
import { Card } from "@/components/Card";
import { Shield, Globe, FileCode, Zap, Map as MapIcon, Crosshair } from "lucide-react";
import { motion } from "framer-motion";

const API_URL = "http://localhost:8000";

export default function ThreatIntelligence() {
    const [rules, setRules] = useState<string>("Loading rules...");
    const [activeTab, setActiveTab] = useState<"dashboard" | "rules">("dashboard");

    useEffect(() => {
        fetch(`${API_URL}/rules`)
            .then(res => res.json())
            .then(data => setRules(data.content))
            .catch(err => setRules("Failed to load rules."));
    }, []);

    return (
        <div className="flex h-screen overflow-hidden bg-slate-950 text-slate-100">
            <Sidebar />

            <main className="flex-1 overflow-y-auto p-0 relative flex flex-col">
                <header className="bg-slate-900 border-b border-slate-800 p-6 flex justify-between items-center">
                    <div>
                        <h1 className="text-3xl font-bold text-white mb-1 flex items-center gap-3">
                            <Shield className="text-rose-500" size={32} />
                            Threat Intelligence
                        </h1>
                        <p className="text-slate-400">Global threat vectors, active campaigns, and detection logic.</p>
                    </div>
                    <div className="flex bg-slate-800 p-1 rounded-lg border border-slate-700">
                        <button
                            onClick={() => setActiveTab("dashboard")}
                            className={`px-4 py-2 rounded-md text-sm font-medium transition-all ${activeTab === "dashboard" ? "bg-slate-700 text-white shadow" : "text-slate-400 hover:text-white"}`}
                        >
                            Overview
                        </button>
                        <button
                            onClick={() => setActiveTab("rules")}
                            className={`px-4 py-2 rounded-md text-sm font-medium transition-all ${activeTab === "rules" ? "bg-slate-700 text-white shadow" : "text-slate-400 hover:text-white"}`}
                        >
                            Rule Library
                        </button>
                    </div>
                </header>

                <div className="flex-1 p-8">
                    {activeTab === "dashboard" ? (
                        <div className="space-y-6 animate-in fade-in zoom-in-95 duration-300">
                            {/* Top Stats */}
                            <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
                                <StatCard title="Global Threat Level" value="ELEVATED" color="text-orange-500" icon={<Zap />} />
                                <StatCard title="Active Campaigns" value="3" color="text-white" icon={<Crosshair />} />
                                <StatCard title="IOCs Tracked" value="12,450" color="text-blue-400" icon={<FileCode />} />
                                <StatCard title="Protected Assets" value="84%" color="text-emerald-400" icon={<Shield />} />
                            </div>

                            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                                {/* Global Map */}
                                <Card className="lg:col-span-2 bg-slate-900 border-slate-800 p-0 relative overflow-hidden min-h-[400px] flex flex-col">
                                    <div className="p-4 border-b border-slate-800 flex justify-between items-center bg-slate-900/80 backdrop-blur z-10">
                                        <h3 className="font-bold text-white flex items-center gap-2"><Globe size={18} className="text-blue-500" /> Global Attack Surface</h3>
                                        <div className="flex gap-2">
                                            <span className="text-xs px-2 py-1 bg-rose-500/20 text-rose-400 rounded border border-rose-500/30">Live Attack Data</span>
                                        </div>
                                    </div>
                                    <div className="flex-1 relative bg-[#0f172a] flex items-center justify-center">
                                        <div className="absolute inset-0 opacity-30 bg-[url('https://upload.wikimedia.org/wikipedia/commons/e/ec/World_map_blank_without_borders.svg')] bg-no-repeat bg-center bg-contain filter invert contrast-50"></div>
                                        {/* Simulated Hotspots */}
                                        <Hotspot top="30%" left="25%" color="bg-rose-500" label="SQL Injection Campaign (US)" />
                                        <Hotspot top="45%" left="48%" color="bg-orange-500" label="Botnet Activity (EU)" />
                                        <Hotspot top="60%" left="75%" color="bg-yellow-500" label="Port Scanning (APAC)" />
                                    </div>
                                </Card>

                                {/* Campaigns */}
                                <div className="space-y-6">
                                    <Card className="bg-slate-900 border-slate-800 p-6">
                                        <h3 className="font-bold text-white mb-4">Active Campaigns</h3>
                                        <div className="space-y-4">
                                            <CampaignItem name="Operation: SQL Storm" type="SQL Injection" severity="Critical" trend="up" />
                                            <CampaignItem name="Botnet: Mirage" type="DDoS / Brute Force" severity="High" trend="stable" />
                                            <CampaignItem name="XSS Wave Alpha" type="Cross-Site Scripting" severity="Medium" trend="down" />
                                        </div>
                                    </Card>

                                    <Card className="bg-slate-900 border-slate-800 p-6">
                                        <h3 className="font-bold text-white mb-4">Latest IOCs</h3>
                                        <ul className="space-y-3 text-sm font-mono">
                                            <li className="flex justify-between text-slate-400"><span>192.168.1.55</span> <span className="text-rose-400">Malware C2</span></li>
                                            <li className="flex justify-between text-slate-400"><span>10.0.0.99</span> <span className="text-orange-400">Scanner</span></li>
                                            <li className="flex justify-between text-slate-400"><span>hash: e4d2...9a1</span> <span className="text-rose-400">Ransomware</span></li>
                                            <li className="flex justify-between text-slate-400"><span>user-agent: "sqlmap"</span> <span className="text-yellow-400">Tool</span></li>
                                        </ul>
                                    </Card>
                                </div>
                            </div>
                        </div>
                    ) : (
                        <div className="h-full animate-in fade-in slide-in-from-bottom-4 duration-300">
                            <Card className="h-full bg-slate-900 border-slate-800 flex flex-col overflow-hidden">
                                <div className="p-4 border-b border-slate-800 bg-slate-950 flex justify-between items-center">
                                    <h3 className="font-bold text-white flex items-center gap-2 font-mono">
                                        <FileCode size={18} className="text-green-400" />
                                        rules.yar
                                    </h3>
                                    <span className="text-xs text-slate-500">Active Detection Logic</span>
                                </div>
                                <div className="flex-1 overflow-auto bg-[#0d1117] p-6">
                                    <pre className="font-mono text-sm text-slate-300 leading-relaxed">
                                        {rules}
                                    </pre>
                                </div>
                            </Card>
                        </div>
                    )}
                </div>
            </main>
        </div>
    );
}

function StatCard({ title, value, color, icon }: any) {
    return (
        <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl flex items-center gap-4 shadow-sm hover:border-slate-700 transition-colors">
            <div className={`p-3 rounded-lg bg-slate-800 ${color}`}>{icon}</div>
            <div>
                <div className="text-slate-400 text-xs font-medium uppercase tracking-wider">{title}</div>
                <div className={`text-xl font-bold ${color.replace('text-', 'text-')}`}>{value}</div>
            </div>
        </div>
    );
}

function Hotspot({ top, left, color, label }: any) {
    return (
        <div className="absolute group cursor-pointer" style={{ top, left }}>
            <span className={`relative flex h-4 w-4`}>
                <span className={`animate-ping absolute inline-flex h-full w-full rounded-full ${color} opacity-75`}></span>
                <span className={`relative inline-flex rounded-full h-4 w-4 ${color} border-2 border-[#0f172a]`}></span>
            </span>
            <div className="absolute left-6 top-0 w-max opacity-0 group-hover:opacity-100 transition-opacity bg-slate-800 text-white text-xs px-2 py-1 rounded border border-slate-700 pointer-events-none z-20">
                {label}
            </div>
        </div>
    );
}

function CampaignItem({ name, type, severity, trend }: any) {
    return (
        <div className="flex items-center justify-between p-3 bg-slate-800/50 rounded-lg border border-slate-800">
            <div>
                <div className="text-white font-medium text-sm">{name}</div>
                <div className="text-xs text-slate-400">{type}</div>
            </div>
            <div className="text-right">
                <div className={`text-xs font-bold px-2 py-0.5 rounded ${severity === "Critical" ? "bg-rose-500/20 text-rose-400" :
                        severity === "High" ? "bg-orange-500/20 text-orange-400" :
                            "bg-yellow-500/20 text-yellow-400"
                    }`}>{severity}</div>
            </div>
        </div>
    );
}
