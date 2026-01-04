'use client';

import { useState, useEffect } from 'react';
import { Sidebar } from "@/components/Sidebar";
import { StatCard } from "@/components/StatCard";
import { LiveTrafficChart } from "@/components/LiveTrafficChart";
import { AlertFeed } from "@/components/AlertFeed";
import { Card } from "@/components/Card";
import { ShieldCheck, Zap, Activity, Users } from "lucide-react";
import { motion } from "framer-motion";

const API_URL = 'http://localhost:8000';

export default function Dashboard() {
  const [stats, setStats] = useState({ total_logs: 0, anomalies_detected: 0, threats_blocked: 0 });
  const [logs, setLogs] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [chartData, setChartData] = useState<any[]>([]);

  // Fetch Data Loop
  useEffect(() => {
    const fetchData = async () => {
      try {
        const statsRes = await fetch(`${API_URL}/stats`);
        const statsData = await statsRes.json();
        setStats(statsData);

        const logsRes = await fetch(`${API_URL}/logs?limit=50`);
        const logsData = await logsRes.json();
        setLogs(logsData);

        const alertsRes = await fetch(`${API_URL}/alerts`);
        const alertsData = await alertsRes.json();
        setAlerts(alertsData);

        // Mocking Chart Data based on total logs to show movement
        setChartData(prev => {
          const now = new Date();
          const timeStr = now.toLocaleTimeString('en-US', { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
          const newVal = { time: timeStr, value: Math.floor(Math.random() * 20) + 10 }; // Simulated volume
          const newData = [...prev, newVal];
          if (newData.length > 20) newData.shift();
          return newData;
        });

      } catch (e) {
        console.error("API connection failed", e);
      }
    };

    fetchData(); // Initial
    const interval = setInterval(fetchData, 2000); // Poll every 2s
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="flex h-screen overflow-hidden bg-slate-950 text-slate-100">
      {/* Sidebar */}
      <Sidebar />

      {/* Main Content */}
      <main className="flex-1 overflow-y-auto p-8 relative">
        {/* Background Grid Decoration - Subtle Enterprise Style */}
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#1e293b_1px,transparent_1px),linear-gradient(to_bottom,#1e293b_1px,transparent_1px)] bg-[size:32px_32px] opacity-20 pointer-events-none"></div>

        <div className="relative z-10 max-w-7xl mx-auto space-y-8">
          {/* Header */}
          <div className="flex justify-between items-center mb-8">
            <div>
              <motion.h2
                initial={{ opacity: 0, y: -20 }}
                animate={{ opacity: 1, y: 0 }}
                className="text-3xl font-bold text-white tracking-tight"
              >
                Security Command Center
              </motion.h2>
              <p className="text-slate-400 mt-1 font-medium">Real-time enterprise threat monitoring ecosystem.</p>
            </div>
            <div className="flex gap-4">
              <span className="flex items-center gap-2 px-4 py-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-sm font-semibold shadow-sm">
                <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse-subtle"></span>
                System Operational
              </span>
            </div>
          </div>

          {/* KPI Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <StatCard
              title="Total Analyzed Events"
              value={stats.total_logs}
              trend="+12% vs last hour"
              trendUp={true}
              color="blue"
              icon={<Activity size={24} />}
            />
            <StatCard
              title="Threats Neutralized"
              value={stats.threats_blocked}
              trend="Action Required"
              trendUp={false}
              color="red"
              icon={<ShieldCheck size={24} />}
            />
            <StatCard
              title="Anomalies Detected"
              value={stats.anomalies_detected}
              trend="+2 new"
              trendUp={false}
              color="orange"
              icon={<Zap size={24} />}
            />
            <StatCard
              title="Active Sessions"
              value="4"
              trend="Stable"
              trendUp={true}
              color="green"
              icon={<Users size={24} />}
            />
          </div>

          {/* Charts & Feed Row */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 h-[400px]">
            {/* Chart takes 2/3 */}
            <div className="lg:col-span-2">
              <LiveTrafficChart data={chartData} />
            </div>
            {/* Alert Feed takes 1/3 */}
            <div className="lg:col-span-1">
              <AlertFeed alerts={alerts} />
            </div>
          </div>

          {/* Recent Logs Table */}
          <Card className="min-h-[300px] bg-slate-800/50 border-slate-700">
            <h3 className="text-lg font-bold text-white mb-6 px-2">Detailed Log Stream</h3>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm text-slate-400">
                <thead className="bg-slate-900/50 uppercase font-semibold text-xs tracking-wider border-b border-slate-700">
                  <tr>
                    <th className="px-6 py-4 rounded-tl-lg">Time</th>
                    <th className="px-6 py-4">Source</th>
                    <th className="px-6 py-4">Event Payload</th>
                    <th className="px-6 py-4 rounded-tr-lg">Analysis</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {logs.slice(0, 8).map((log: any, i) => (
                    <tr key={i} className="hover:bg-slate-700/30 transition-colors">
                      <td className="px-6 py-4 whitespace-nowrap font-mono text-xs text-slate-500 hover:text-slate-300 transition-colors">
                        {new Date(log.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="px-6 py-4 font-mono text-xs text-slate-300">{log.source_ip}</td>
                      <td className="px-6 py-4 max-w-xs truncate text-slate-300" title={log.message}>{log.message || log.raw_message}</td>
                      <td className="px-6 py-4">
                        {log.analysis.is_threat ? (
                          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-rose-500/10 text-rose-400 border border-rose-500/20 text-xs font-medium">
                            <span className="w-1.5 h-1.5 rounded-full bg-rose-500"></span> Threat
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-xs font-medium">
                            Clean
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>

        </div>
      </main>
    </div>
  );
}
