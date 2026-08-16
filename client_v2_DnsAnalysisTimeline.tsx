import { createSignal, createMemo, Show, For } from 'solid-js';

import theme from 'panel/lib/theme';
import { formatDuration, formatTime } from 'panel/helpers/formatters';
import { LineChart } from 'panel/common/ui/Charts';

import s from './DnsAnalysisTimeline.module.pcss';

interface TimelineProps {
    requests: Array<{
        id: string;
        timestamp: string;
        question: { name: string; type: string };
        clientIP: string;
        timeline: {
            totalDuration: number;
            initialProcessingDuration: number;
            filteringBeforeDuration: number;
            upstreamDuration: number;
            filteringAfterDuration: number;
        };
    }> | null;
}

export const DnsAnalysisTimeline = ({ requests }: TimelineProps) => {
    if (!requests || requests.length === 0) {
        return <div class={s.empty}>No timeline data available</div>;
    }

    // Sort by timestamp descending (newest first)
    const sortedRequests = [...requests].sort((a, b) => 
        new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    );

    // Prepare chart data - last 100 requests
    const chartData = createMemo(() => 
        sortedRequests.slice(0, 100).reverse().map((req, index) => ({
            x: index,
            total: req.timeline.totalDuration / 1e6,
            initial: req.timeline.initialProcessingDuration / 1e6,
            filteringBefore: req.timeline.filteringBeforeDuration / 1e6,
            upstream: req.timeline.upstreamDuration / 1e6,
            filteringAfter: req.timeline.filteringAfterDuration / 1e6,
        }))
    );

    return (
        <div class={s.timeline}>
            <h3 class={s.sectionTitle}>Request Processing Timeline</h3>
            
            <div class={s.chartContainer}>
                <LineChart 
                    data={chartData()} 
                    xKey="x"
                    yKeys={['total', 'initial', 'filteringBefore', 'upstream', 'filteringAfter']}
                    labels={['Total', 'Initial', 'Filtering Before', 'Upstream', 'Filtering After']}
                    colors={['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6']}
                />
            </div>

            <div class={s.tableContainer}>
                <table class={s.table}>
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Domain</th>
                            <th>Type</th>
                            <th>Client</th>
                            <th>Total</th>
                            <th>Initial</th>
                            <th>Filter Before</th>
                            <th>Upstream</th>
                            <th>Filter After</th>
                        </tr>
                    </thead>
                    <tbody>
                        <For each={sortedRequests.slice(0, 50)}>
                            {(req) => (
                                <tr>
                                    <td class={s.timeCell}>{formatTime(req.timestamp)}</td>
                                    <td class={s.domainCell}>{req.question.name}</td>
                                    <td class={s.typeCell}>{req.question.type}</td>
                                    <td class={s.clientCell}>{req.clientIP}</td>
                                    <td class={s.durationCell}>{formatDuration(req.timeline.totalDuration / 1e6)}</td>
                                    <td class={s.durationCell}>{formatDuration(req.timeline.initialProcessingDuration / 1e6)}</td>
                                    <td class={s.durationCell}>{formatDuration(req.timeline.filteringBeforeDuration / 1e6)}</td>
                                    <td class={s.durationCell}>{formatDuration(req.timeline.upstreamDuration / 1e6)}</td>
                                    <td class={s.durationCell}>{formatDuration(req.timeline.filteringAfterDuration / 1e6)}</td>
                                </tr>
                            )}
                        </For>
                    </tbody>
                </table>
            </div>
        </div>
    );
};