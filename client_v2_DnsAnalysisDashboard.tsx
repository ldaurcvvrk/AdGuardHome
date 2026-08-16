import { createSignal, createMemo, createEffect, onCleanup, Show, For } from 'solid-js';

import theme from 'panel/lib/theme';
import { PageLoader } from 'panel/common/ui/Loader';
import { dnsAnalysisState, getDnsAnalysisStats, getDnsAnalysisRequests, getDnsAnalysisConfig } from 'panel/stores/dnsanalysis';
import { ONE_SECOND_IN_MS } from 'panel/helpers/constants';

import { Header } from './Header/Header';
import { StatCards } from './StatCards';
import { EmptyState } from './EmptyState/EmptyState';
import { DnsAnalysisOverview } from './DnsAnalysisOverview';
import { DnsAnalysisTimeline } from './DnsAnalysisTimeline';
import { DnsAnalysisFiltering } from './DnsAnalysisFiltering';
import { DnsAnalysisUpstreams } from './DnsAnalysisUpstreams';
import { DnsAnalysisCache } from './DnsAnalysisCache';
import { DnsAnalysisRequestsTable } from './DnsAnalysisRequestsTable';

import s from './DnsAnalysisDashboard.module.pcss';

export const DnsAnalysisDashboard = () => {
    const [selectedPeriod, setSelectedPeriod] = createSignal(3600000); // 1 hour default
    const [selectedTab, setSelectedTab] = createSignal<'overview' | 'timeline' | 'filtering' | 'upstreams' | 'cache' | 'requests'>('overview');
    const [refreshInterval, setRefreshInterval] = createSignal(5000);
    let timerRef: ReturnType<typeof setInterval> | null = null;

    const periodOptions = createMemo(() => [
        { value: 300000, label: 'Last 5 min' },
        { value: 900000, label: 'Last 15 min' },
        { value: 3600000, label: 'Last 1 hour' },
        { value: 21600000, label: 'Last 6 hours' },
        { value: 86400000, label: 'Last 24 hours' },
    ]);

    const startAutoRefresh = () => {
        if (timerRef) {
            clearInterval(timerRef);
        }
        timerRef = setInterval(() => {
            getDnsAnalysisStats(selectedPeriod());
            getDnsAnalysisRequests(selectedPeriod());
        }, refreshInterval());
    };

    createEffect(() => {
        const period = selectedPeriod();
        getDnsAnalysisStats(period);
        getDnsAnalysisRequests(period);
        getDnsAnalysisConfig();
        startAutoRefresh();
    });

    onCleanup(() => {
        if (timerRef) {
            clearInterval(timerRef);
        }
    });

    const handleRefresh = () => {
        getDnsAnalysisStats(selectedPeriod());
        getDnsAnalysisRequests(selectedPeriod());
    };

    const handlePeriodChange = (period: number) => {
        setSelectedPeriod(period);
    };

    const handleTabChange = (tab: 'overview' | 'timeline' | 'filtering' | 'upstreams' | 'cache' | 'requests') => {
        setSelectedTab(tab);
    };

    const isLoading = () => dnsAnalysisState.processingStats || dnsAnalysisState.processingRequests;

    return (
        <div class={theme.layout.container}>
            <div class={theme.layout.containerIn}>
                <Header
                    enabled={dnsAnalysisState.enabled}
                    processing={isLoading()}
                    selectedPeriod={selectedPeriod()}
                    periodOptions={periodOptions()}
                    selectedTab={selectedTab()}
                    onPeriodChange={handlePeriodChange}
                    onTabChange={handleTabChange}
                    onRefresh={handleRefresh}
                />

                <Show
                    when={!isLoading()}
                    fallback={
                        <div class={s.loader}>
                            <PageLoader />
                        </div>
                    }
                >
                    <Show when={dnsAnalysisState.enabled} fallback={<EmptyState mode="disabled" class={s.emptyState} />}>
                        <div class={s.statContainer}>
                            <StatCards
                                totalRequests={dnsAnalysisState.stats?.totalRequests || 0}
                                avgLatency={dnsAnalysisState.stats?.avgLatencyNs || 0}
                                cacheHitRate={dnsAnalysisState.stats?.cacheHitRate || 0}
                                blockedCount={dnsAnalysisState.stats?.blockedCount || 0}
                                errorCount={dnsAnalysisState.stats?.errorCount || 0}
                            />

                            <Show when={selectedTab() === 'overview'}>
                                <DnsAnalysisOverview stats={dnsAnalysisState.stats} />
                            </Show>

                            <Show when={selectedTab() === 'timeline'}>
                                <DnsAnalysisTimeline requests={dnsAnalysisState.requests} />
                            </Show>

                            <Show when={selectedTab() === 'filtering'}>
                                <DnsAnalysisFiltering stats={dnsAnalysisState.stats} requests={dnsAnalysisState.requests} />
                            </Show>

                            <Show when={selectedTab() === 'upstreams'}>
                                <DnsAnalysisUpstreams stats={dnsAnalysisState.stats} requests={dnsAnalysisState.requests} />
                            </Show>

                            <Show when={selectedTab() === 'cache'}>
                                <DnsAnalysisCache stats={dnsAnalysisState.stats} requests={dnsAnalysisState.requests} />
                            </Show>

                            <Show when={selectedTab() === 'requests'}>
                                <DnsAnalysisRequestsTable requests={dnsAnalysisState.requests} />
                            </Show>
                        </div>
                    </Show>
                </Show>
            </div>
        </div>
    );
};