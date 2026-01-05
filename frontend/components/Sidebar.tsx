import { Home, Activity, Settings, Shield, FileText, Menu, Zap } from "lucide-react";
import { useState } from "react";
import { motion } from "framer-motion";
import Link from "next/link";
import { usePathname } from "next/navigation";

export function Sidebar() {
    const [collapsed, setCollapsed] = useState(false);
    const pathname = usePathname();

    const items = [
        { icon: <Home size={20} />, label: "Dashboard", href: "/" },
        { icon: <Activity size={20} />, label: "Live Monitoring", href: "/live" },
        { icon: <FileText size={20} />, label: "Logs Explorer", href: "/logs" },
        { icon: <Shield size={20} />, label: "Threat Intelligence", href: "/threats" },
        { icon: <Zap size={20} />, label: "Attack Simulator", href: "/simulator" },
        { icon: <Settings size={20} />, label: "Settings", href: "/settings" },
    ];

    return (
        <motion.aside
            initial={{ width: 250 }}
            animate={{ width: collapsed ? 80 : 250 }}
            className="h-screen bg-slate-900 border-r border-slate-700 flex flex-col z-20 shadow-xl"
        >
            <div className="p-6 flex justify-between items-center border-b border-slate-800">
                {!collapsed && (
                    <motion.h1
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        className="text-xl font-bold text-white tracking-tight"
                    >
                        Alert<span className="text-primary">Forge</span>
                    </motion.h1>
                )}
                <button onClick={() => setCollapsed(!collapsed)} className="p-2 hover:bg-slate-800 rounded-lg text-slate-400 transition-colors">
                    <Menu size={20} />
                </button>
            </div>

            <nav className="flex-1 px-3 space-y-1 mt-6">
                {items.map((item) => {
                    const isActive = pathname === item.href || (item.href === "/" && pathname === "/");
                    return (
                        <Link
                            key={item.label}
                            href={item.href}
                            className={`flex items-center gap-3 px-4 py-3 rounded-lg transition-all font-medium ${isActive
                                ? "bg-primary/10 text-primary border border-primary/20"
                                : "text-slate-400 hover:bg-slate-800 hover:text-slate-200"
                                }`}
                        >
                            {item.icon}
                            {!collapsed && <motion.span initial={{ opacity: 0 }} animate={{ opacity: 1 }}>{item.label}</motion.span>}
                        </Link>
                    );
                })}
            </nav>

            <div className="p-4 border-t border-slate-800 bg-slate-900/50">
                <div className={`flex items-center gap-3 ${collapsed ? "justify-center" : ""}`}>
                    <div className="w-9 h-9 rounded-full bg-indigo-600 flex items-center justify-center text-sm font-bold text-white shadow-lg">
                        B
                    </div>
                    {!collapsed && (
                        <div className="overflow-hidden">
                            <div className="text-sm font-semibold text-slate-200">Bala</div>
                            <div className="text-xs text-slate-400">Security Admin</div>
                        </div>
                    )}
                </div>
            </div>
        </motion.aside>
    );
}
