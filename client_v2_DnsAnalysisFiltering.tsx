import { createMemo, For } from 'solid-js';

import theme from 'panel/lib/theme';
import { formatNumber, formatPercent } from 'panel/helpers/formatters';
import { BarChart, PieChart } from 'panel/common/ui/Charts';

import s from './DnsAnalysisFiltering.module.pcss';

interface FilteringProps {
    stats: {
        byFilterReason: Record<string, number>;
        blockedCount: number;
        modifiedCount: number;
    } | null;
    requests: Array<{
        filtering: {
            matched: boolean;
            reason: string;
            matchedRules: string[];
            matchedFilterLists: string[];
            serviceName: string;
            blockedIPv4: string;
            blockedIPv6: string;
            cname: string;
            blockingMode: string;
            safeSearchApplied: boolean;
            safeBrowsingHit: boolean;
            parentalHit: boolean;
            rewritesApplied: boolean;
        };
    }> | null;
}

export const DnsAnalysisFiltering = ({ stats, requests }: FilteringProps) => {
    if (!stats) return null;

    const filterReasonData = createMemo(() => Object.entries(stats.byFilterReason).map(([name, value]) => ({ name, value })));

    // Analyze filter list effectiveness
    const filterListStats = createMemo(() => {
        const counts: Record<string, number> = {};
        if (requests) {
            for (const req of requests) {
                if (req.filtering.matchedFilterLists) {
                    for (const list of req.filtering.matchedFilterLists) {
                        counts[list] = (counts[list] || 0) + 1;
                    }
                }
            }
        }
        return Object.entries(counts)
            .map(([name, value]) => ({ name, value }))
            .sort((a, b) => b.value - a.value)
            .slice(0, 20);
    });

    // Analyze top blocked domains
    const blockedDomains = createMemo(() => {
        const counts: Record<string, number> = {};
        if (requests) {
            for (const req of requests) {
                if (req.filtering.matched && req.filtering.reason === 'FilteredBlockList') {
                    // We'd need the domain from the request - for now use a placeholder
                    counts[req.filtering.matchedRules?.[0] || 'unknown'] = (counts[req.filtering.matchedRules?.[0] || 'unknown'] || 0) + 1;
                }
            }
        }
        return Object.entries(counts)
            .map(([name, value]) => ({ name, value }))
            .sort((a, b) => b.value - a.value)
            .slice(0, 20);
    });

    return (
        <div class={s.filtering}>
            <div class={s.grid}>
                <div class={s.card}>
                    <h3 class={s.cardTitle}>Filter Reasons Distribution</h3>
                    <PieChart data={filterReasonData()} />
                </div>

                <div class={s.card}>
                    <h3 class={s.cardTitle}>Top Filter Lists by Hits</h3>
                    <BarChart data={filterListStats()} horizontal={true} />
                </div>
            </div>

            <div class={s.grid}>
                <div class={s.card}>
                    <h3 class={s.cardTitle}>Top Blocked Rules</h3>
                    <BarChart data={blockedDomains()} horizontal={true} />
                </div>

                <div class={s.card}>
                    <h3 class={s.cardTitle}>Filtering Effectiveness</h3>
                    <div class={s.effectivenessGrid}>
                        <div class={s.effItem}>
                            <span class={s.effLabel}>Total Blocked</span>
                            <span class={s.effValue}>{formatNumber(stats.blockedCount)}</span>
                        </div>
                        <div class={s.effItem}>
                            <span class={s.effLabel}>Modified Responses</span>
                            <span class={s.effValue}>{formatNumber(stats.modifiedCount)}</span>
                        </div>
                        <div class={s.effItem}>
                            <span class={s.effLabel}>Block Rate</span>
                            <span class={s.effValue}>{stats.totalRequests > 0 ? formatPercent(stats.blockedCount / stats.totalRequests) : '0%'}</span>
                        </div>
                        <div class={s.effItem}>
                            <span class={s.effLabel}>Modification Rate</span>
                            <span class={s.effValue}>{stats.totalRequests > 0 ? formatPercent(stats.modifiedCount / stats.totalRequests) : '0%'}</span>
                        </div>
                    </div>
                </div>
            </div>

            <div class={s.section}>
                <h3 class={s.sectionTitle}>Safe Browsing & Parental Hits</h3>
                <div class={s.safetyGrid}>
                    <div class={s.safetyCard}>
                        <span class={s.safetyLabel}>Safe Browsing Hits</span>
                        <span class={s.safetyValue}>
                            {requests?.filter(r => r.filtering.safeBrowsingHit).length || 0}
                        </span>
                    </div>
                    <div class={s.safetyCard}>
                        <span class={s.safetyLabel}>Parental Control Hits</span>
                        <span class={s.safetyValue}>
                            {requests?.filter(r => r.filtering.parentalHit).length || 0}
                        </span>
                    </div>
                    <div class={s.safetyCard}>
                        <span class={s.safetyLabel}>Safe Search Applied</span>
                        <span class={s.safetyValue}>
                            {requests?.filter(r => r.filtering.safeSearchApplied).length || 0}
                        </span>
                    </div>
                    <div class={s.safetyCard}>
                        <span class={s.safetyLabel}>Rewrites Applied</span>
                        <span class={s.safetyValue}>
                            {requests?.filter(r => r.filtering.rewritesApplied).length || 0}
                        </span>
                    </div>
                </div>
            </div>
        </div>
    );
};