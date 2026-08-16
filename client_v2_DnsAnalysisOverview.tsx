import { createSignal, createMemo, createEffect, onCleanup, Show, For } from 'solid-js';

import theme from 'panel/lib/theme';
import { formatDuration, formatNumber } from 'panel/helpers/formatters';
import { Chart, LineChart, BarChart, PieChart } from 'panel/common/ui/Charts';

import s from './DnsAnalysisOverview.module.pcss';

interface OverviewProps {
    stats: {
        totalRequests: number;
        byProtocol: Record<string, number>;
        byRCode: Record<string, number>;
        byFilterReason: Record<string, number>;
        byUpstream: Record<string, number>;
        cacheHitRate: number;
        avgLatencyNs: number;
        avgUpstreamLatencyNs: number;
        blockedCount: number;
        modifiedCount: number;
        errorCount: number;
    } | null;
}

export const DnsAnalysisOverview = ({ stats }: OverviewProps) => {
    if (!stats) return null;

    const protocolData = createMemo(() => Object.entries(stats.byProtocol).map(([name, value]) => ({ name, value })));
    const rcodeData = createMemo(() => Object.entries(stats.byRCode).map(([name, value]) => ({ name, value })));
    const filterReasonData = createMemo(() => Object.entries(stats.byFilterReason).map(([name, value]) => ({ name, value })));
    const upstreamData = createMemo(() => Object.entries(stats.byUpstream).map(([name, value]) => ({ name, value })));

    return (
        <div class={s.overview}>
            <div class={s.grid}>
                <div class={s.card}>
                    <h3 class={s.cardTitle}>Protocol Distribution</h3>
                    <PieChart data={protocolData()} />
                </div>

                <div class={s.card}>
                    <h3 class={s.cardTitle}>Response Codes</h3>
                    <PieChart data={rcodeData()} />
                </div>

                <div class={s.card}>
                    <h3 class={s.cardTitle}>Filter Reasons</h3>
                    <BarChart data={filterReasonData()} horizontal={true} />
                </div>

                <div class={s.card}>
                    <h3 class={s.cardTitle}>Upstream Usage</h3>
                    <BarChart data={upstreamData()} horizontal={true} />
                </div>
            </div>

            <div class={s.metricsGrid}>
                <div class={s.metricCard}>
                    <span class={s.metricLabel}>Avg Total Latency</span>
                    <span class={s.metricValue}>{formatDuration(stats.avgLatencyNs / 1e6)}</span>
                </div>
                <div class={s.metricCard}>
                    <span class={s.metricLabel}>Avg Upstream Latency</span>
                    <span class={s.metricValue}>{formatDuration(stats.avgUpstreamLatencyNs / 1e6)}</span>
                </div>
                <div class={s.metricCard}>
                    <span class={s.metricLabel}>Cache Hit Rate</span>
                    <span class={s.metricValue}>{(stats.cacheHitRate * 100).toFixed(1)}%</span>
                </div>
                <div class={s.metricCard}>
                    <span class={s.metricLabel}>Blocked Requests</span>
                    <span class={s.metricValue}>{formatNumber(stats.blockedCount)}</span>
                </div>
                <div class={s.metricCard}>
                    <span class={s.metricLabel}>Modified Responses</span>
                    <span class={s.metricValue}>{formatNumber(stats.modifiedCount)}</span>
                </div>
                <div class={s.metricCard}>
                    <span class={s.metricLabel}>Errors</span>
                    <span class={s.metricValue}>{formatNumber(stats.errorCount)}</span>
                </div>
            </div>
        </div>
    );
};