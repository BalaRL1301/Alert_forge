import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, CartesianGrid } from 'recharts';
import { Card } from "./Card";

interface DataPoint {
    time: string;
    value: number;
}

export function LiveTrafficChart({ data, height = 300 }: { data: DataPoint[], height?: number }) {
    // Mock data if empty
    const chartData = data.length > 0 ? data : [
        { time: '10:00', value: 12 },
        { time: '10:01', value: 19 },
        { time: '10:02', value: 3 },
        { time: '10:03', value: 5 },
        { time: '10:04', value: 2 },
    ];

    return (
        <Card className={`h-[${height}px] w-full`}>
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-blue-500 animate-pulse" />
                Network Traffic Volume
            </h3>
            <div style={{ height: height - 80 }} className="w-full">
                <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={chartData}>
                        <defs>
                            <linearGradient id="colorValue" x1="0" y1="0" x2="0" y2="1">
                                <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                                <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                            </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" stroke="#333" vertical={false} />
                        <XAxis dataKey="time" stroke="#666" tick={{ fill: '#666', fontSize: 12 }} />
                        <YAxis stroke="#666" tick={{ fill: '#666', fontSize: 12 }} />
                        <Tooltip
                            contentStyle={{ backgroundColor: '#111', border: '1px solid #333', borderRadius: '8px' }}
                            itemStyle={{ color: '#fff' }}
                        />
                        <Area
                            type="monotone"
                            dataKey="value"
                            stroke="#3b82f6"
                            strokeWidth={2}
                            fillOpacity={1}
                            fill="url(#colorValue)"
                        />
                    </AreaChart>
                </ResponsiveContainer>
            </div>
        </Card>
    );
}
