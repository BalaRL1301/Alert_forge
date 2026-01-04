import { Card } from "./Card";
import { ArrowUpRight, ArrowDownRight, Activity } from "lucide-react";
import { cn } from "@/lib/utils";

interface StatCardProps {
    title: string;
    value: string | number;
    trend?: string;
    trendUp?: boolean;
    icon?: React.ReactNode;
    color?: "blue" | "red" | "green" | "orange";
}

export function StatCard({ title, value, trend, trendUp, icon, color = "blue" }: StatCardProps) {
    const colorMap = {
        blue: "text-sky-400 bg-sky-500/10 border-sky-500/20",
        red: "text-rose-400 bg-rose-500/10 border-rose-500/20",
        green: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20",
        orange: "text-amber-400 bg-amber-500/10 border-amber-500/20",
    };

    // Extract base color class for the icon background using the key directly
    const baseColorClass = colorMap[color];

    return (
        <Card className="relative group hover:border-slate-600 transition-colors border-slate-700 bg-slate-800/50">
            <div className={cn("absolute right-4 top-4 p-2.5 rounded-lg transition-opacity", baseColorClass)}>
                {icon || <Activity size={20} />}
            </div>

            <h3 className="text-sm font-medium text-slate-400 mb-2">{title}</h3>
            <div className="flex items-baseline gap-3">
                <span className="text-3xl font-bold tracking-tight text-white">
                    {value}
                </span>
                {trend && (
                    <div className={cn("flex items-center text-xs font-medium px-2 py-0.5 rounded-full",
                        trendUp ? "text-emerald-400 bg-emerald-400/10" : "text-rose-400 bg-rose-400/10")}>
                        {trendUp ? <ArrowUpRight size={12} className="mr-1" /> : <ArrowDownRight size={12} className="mr-1" />}
                        {trend}
                    </div>
                )}
            </div>
        </Card>
    );
}
