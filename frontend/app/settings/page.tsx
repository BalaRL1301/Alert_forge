"use client";

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Save, Shield, Bell, AlertTriangle } from "lucide-react";

export default function Settings() {
    const [settings, setSettings] = useState({
        auto_block: true,
        block_threshold: 0.8,
        email_alerts: false,
        admin_email: "",
        smtp_server: "smtp.gmail.com",
        smtp_port: 587,
        smtp_username: "",
        smtp_password: ""
    });
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [message, setMessage] = useState("");

    useEffect(() => {
        fetch("http://localhost:8000/settings")
            .then(res => res.json())
            .then(data => {
                setSettings(data);
                setLoading(false);
            })
            .catch(err => {
                console.error("Failed to fetch settings:", err);
                setLoading(false);
            });
    }, []);

    const handleChange = (key: string, value: any) => {
        setSettings(prev => ({ ...prev, [key]: value }));
    };

    const handleSave = async () => {
        setSaving(true);
        setMessage("");
        try {
            const res = await fetch("http://localhost:8000/settings", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(settings)
            });
            if (res.ok) {
                setMessage("Settings saved successfully!");
                setTimeout(() => setMessage(""), 3000);
            } else {
                setMessage("Failed to save settings.");
            }
        } catch (err) {
            console.error(err);
            setMessage("Error saving settings.");
        } finally {
            setSaving(false);
        }
    };

    if (loading) return <div className="p-10 text-slate-400">Loading settings...</div>;

    return (
        <div className="p-8 space-y-8">
            <header>
                <h1 className="text-3xl font-bold text-white mb-2">Settings</h1>
                <p className="text-slate-400">Configure detection thresholds and automated responses.</p>
            </header>

            <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                className="grid gap-6 max-w-2xl"
            >
                {/* Security Section */}
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-6">
                    <div className="flex items-center gap-3 text-lg font-semibold text-white border-b border-slate-800 pb-4">
                        <Shield className="text-primary" />
                        <h2>Security Response</h2>
                    </div>

                    <div className="flex items-center justify-between">
                        <div>
                            <div className="text-slate-200 font-medium">Auto-Block Threats</div>
                            <div className="text-sm text-slate-400">Automatically block IPs with high confidence threats.</div>
                        </div>
                        <button
                            onClick={() => handleChange("auto_block", !settings.auto_block)}
                            className={`w-14 h-7 rounded-full p-1 transition-colors ${settings.auto_block ? "bg-primary" : "bg-slate-700"}`}
                        >
                            <div className={`w-5 h-5 bg-white rounded-full shadow-md transform transition-transform ${settings.auto_block ? "translate-x-7" : "translate-x-0"}`} />
                        </button>
                    </div>

                    <div className="space-y-3">
                        <div className="flex justify-between">
                            <div>
                                <div className="text-slate-200 font-medium">Blocking Threshold</div>
                                <div className="text-sm text-slate-400">Minimum confidence score to trigger auto-block (0.0 - 1.0).</div>
                            </div>
                            <span className="font-mono text-primary font-bold">{settings.block_threshold}</span>
                        </div>
                        <input
                            type="range"
                            min="0"
                            max="1"
                            step="0.05"
                            value={settings.block_threshold}
                            onChange={(e) => handleChange("block_threshold", parseFloat(e.target.value))}
                            className="w-full bg-slate-800 h-2 rounded-lg appearance-none cursor-pointer accent-primary"
                        />
                    </div>
                </div>

                {/* Notifications Section */}
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-6">
                    <div className="flex items-center gap-3 text-lg font-semibold text-white border-b border-slate-800 pb-4">
                        <Bell className="text-blue-400" />
                        <h2>Notifications</h2>
                    </div>

                    <div className="flex items-center justify-between">
                        <div>
                            <div className="text-slate-200 font-medium">Email Alerts</div>
                            <div className="text-sm text-slate-400">Receive email summaries of high-severity incidents.</div>
                        </div>
                        <button
                            onClick={() => handleChange("email_alerts", !settings.email_alerts)}
                            className={`w-14 h-7 rounded-full p-1 transition-colors ${settings.email_alerts ? "bg-blue-500" : "bg-slate-700"}`}
                        >
                            <div className={`w-5 h-5 bg-white rounded-full shadow-md transform transition-transform ${settings.email_alerts ? "translate-x-7" : "translate-x-0"}`} />
                        </button>
                    </div>

                    {settings.email_alerts && (
                        <div className="pt-2 animate-in fade-in slide-in-from-top-2 duration-200">
                            <label className="block text-sm font-medium text-slate-300 mb-1">Admin Email Address</label>
                            <input
                                type="email"
                                value={settings.admin_email || ""}
                                onChange={(e) => handleChange("admin_email", e.target.value)}
                                placeholder="admin@company.com"
                                className="w-full bg-slate-800 border border-slate-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                            />
                        </div>
                    )}
                </div>

                <div className="flex items-center gap-4">
                    <button
                        onClick={handleSave}
                        disabled={saving}
                        className="bg-primary hover:bg-primary/90 text-white px-6 py-2 rounded-lg flex items-center gap-2 font-medium disabled:opacity-50 transition-colors"
                    >
                        <Save size={18} />
                        {saving ? "Saving..." : "Save Changes"}
                    </button>
                    {message && (
                        <span className={`text-sm ${message.includes("Failed") || message.includes("Error") ? "text-red-400" : "text-green-400"}`}>
                            {message}
                        </span>
                    )}
                </div>

            </motion.div>
        </div>
    );
}
