// Chart.js Attack Types Chart
// Extracted from dashboard_template.py (lines ~3370-3550)

let attackTypesChart = null;
let attackTypesChartLoaded = false;

/**
 * Load an attack types doughnut chart into a canvas element.
 * @param {string} [canvasId='attack-types-chart'] - Canvas element ID
 * @param {string} [ipFilter] - Optional IP address to scope results
 * @param {string} [legendPosition='right'] - Legend position
 */
async function loadAttackTypesChart(canvasId, ipFilter, legendPosition) {
    canvasId = canvasId || 'attack-types-chart';
    legendPosition = legendPosition || 'right';
    const DASHBOARD_PATH = window.__DASHBOARD_PATH__ || '';

    try {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;

        let url = DASHBOARD_PATH + '/api/attack-types-stats?limit=10';
        if (ipFilter) url += '&ip_filter=' + encodeURIComponent(ipFilter);

        const response = await fetch(url, {
            cache: 'no-store',
            headers: {
                'Cache-Control': 'no-cache',
                'Pragma': 'no-cache'
            }
        });

        if (!response.ok) throw new Error('Failed to fetch attack types');

        const data = await response.json();
        const attackTypes = data.attack_types || [];

        if (attackTypes.length === 0) {
            canvas.parentElement.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:#8b949e;font-size:13px;">No attack data</div>';
            return;
        }

        const labels = attackTypes.map(item => item.type);
        const counts = attackTypes.map(item => item.count);
        const maxCount = Math.max(...counts);

        // Hash function to generate consistent color from string
        function hashCode(str) {
            let hash = 0;
            for (let i = 0; i < str.length; i++) {
                const char = str.charCodeAt(i);
                hash = ((hash << 5) - hash) + char;
                hash = hash & hash; // Convert to 32bit integer
            }
            return Math.abs(hash);
        }

        // Dynamic color generator based on hash
        function generateColorFromHash(label) {
            const hash = hashCode(label);
            const hue = (hash % 360); // 0-360 for hue
            const saturation = 70 + (hash % 20); // 70-90 for vibrant colors
            const lightness = 50 + (hash % 10); // 50-60 for brightness

            const bgColor = `hsl(${hue}, ${saturation}%, ${lightness}%)`;
            const borderColor = `hsl(${hue}, ${saturation + 5}%, ${lightness - 10}%)`; // Darker border
            const hoverColor = `hsl(${hue}, ${saturation - 10}%, ${lightness + 8}%)`; // Lighter hover

            return { bg: bgColor, border: borderColor, hover: hoverColor };
        }

        // Generate colors dynamically for each attack type
        const backgroundColors = labels.map(label => generateColorFromHash(label).bg);
        const borderColors = labels.map(label => generateColorFromHash(label).border);
        const hoverColors = labels.map(label => generateColorFromHash(label).hover);

        // Create or update chart (track per canvas)
        if (!loadAttackTypesChart._instances) loadAttackTypesChart._instances = {};
        if (loadAttackTypesChart._instances[canvasId]) {
            loadAttackTypesChart._instances[canvasId].destroy();
        }

        const ctx = canvas.getContext('2d');
        const chartInstance = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: counts,
                    backgroundColor: backgroundColors,
                    borderColor: '#0d1117',
                    borderWidth: 3,
                    hoverBorderColor: '#58a6ff',
                    hoverBorderWidth: 4,
                    hoverOffset: 10
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: legendPosition,
                        labels: {
                            color: '#c9d1d9',
                            font: {
                                size: 12,
                                weight: '500',
                                family: "'Segoe UI', Tahoma, Geneva, Verdana"
                            },
                            padding: 16,
                            usePointStyle: true,
                            pointStyle: 'circle',
                            generateLabels: (chart) => {
                                const data = chart.data;
                                return data.labels.map((label, i) => ({
                                    text: `${label} (${data.datasets[0].data[i]})`,
                                    fillStyle: data.datasets[0].backgroundColor[i],
                                    hidden: false,
                                    index: i,
                                    pointStyle: 'circle'
                                }));
                            }
                        }
                    },
                    tooltip: {
                        enabled: true,
                        backgroundColor: 'rgba(22, 27, 34, 0.95)',
                        titleColor: '#58a6ff',
                        bodyColor: '#c9d1d9',
                        borderColor: '#58a6ff',
                        borderWidth: 2,
                        padding: 14,
                        titleFont: {
                            size: 14,
                            weight: 'bold',
                            family: "'Segoe UI', Tahoma, Geneva, Verdana"
                        },
                        bodyFont: {
                            size: 13,
                            family: "'Segoe UI', Tahoma, Geneva, Verdana"
                        },
                        caretSize: 8,
                        caretPadding: 12,
                        callbacks: {
                            label: function(context) {
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const percentage = ((context.parsed / total) * 100).toFixed(1);
                                return `${context.label}: ${percentage}%`;
                            }
                        }
                    }
                },
                animation: {
                    enabled: false
                },
                onHover: (event, activeElements) => {
                    canvas.style.cursor = activeElements.length > 0 ? 'pointer' : 'default';
                }
            },
            plugins: [{
                id: 'customCanvasBackgroundColor',
                beforeDraw: (chart) => {
                    if (chart.ctx) {
                        chart.ctx.save();
                        chart.ctx.globalCompositeOperation = 'destination-over';
                        chart.ctx.fillStyle = 'rgba(0,0,0,0)';
                        chart.ctx.fillRect(0, 0, chart.width, chart.height);
                        chart.ctx.restore();
                    }
                }
            }]
        });

        loadAttackTypesChart._instances[canvasId] = chartInstance;
        attackTypesChart = chartInstance;
        attackTypesChartLoaded = true;
    } catch (err) {
        console.error('Error loading attack types chart:', err);
    }
}


/**
 * Load a daily attack trends line chart with interactive legend filtering.
 * Clicking a legend item filters the Detected Attack Types table via HTMX.
 * @param {string} [canvasId='attack-trends-chart'] - Canvas element ID
 */
let attackTrendsChart = null;

async function loadAttackTrendsChart(canvasId) {
    canvasId = canvasId || 'attack-trends-chart';
    const DASHBOARD_PATH = window.__DASHBOARD_PATH__ || '';

    try {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;

        const response = await fetch(DASHBOARD_PATH + '/api/attack-types-daily?limit=10&days=30', {
            cache: 'no-store',
            headers: { 'Cache-Control': 'no-cache', 'Pragma': 'no-cache' }
        });

        if (!response.ok) throw new Error('Failed to fetch daily attack data');

        const data = await response.json();
        const attackTypes = data.attack_types || [];
        const dates = data.dates || [];

        if (attackTypes.length === 0) {
            canvas.parentElement.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:#8b949e;font-size:13px;">No attack data</div>';
            return;
        }

        // Hash-based consistent colors (reuse from doughnut chart)
        function hashCode(str) {
            let hash = 0;
            for (let i = 0; i < str.length; i++) {
                hash = ((hash << 5) - hash) + str.charCodeAt(i);
                hash = hash & hash;
            }
            return Math.abs(hash);
        }

        function colorFromHash(label, alpha) {
            const h = hashCode(label);
            const hue = h % 360;
            const sat = 70 + (h % 20);
            const lit = 50 + (h % 10);
            return alpha !== undefined
                ? `hsla(${hue}, ${sat}%, ${lit}%, ${alpha})`
                : `hsl(${hue}, ${sat}%, ${lit}%)`;
        }

        // Format dates as short labels (e.g. "Mar 15")
        const shortLabels = dates.map(d => {
            const dt = new Date(d + 'T00:00:00');
            return dt.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
        });

        const datasets = attackTypes.map(at => ({
            label: `${at.type} (${at.total})`,
            data: at.daily,
            borderColor: colorFromHash(at.type),
            backgroundColor: colorFromHash(at.type, 0.1),
            borderWidth: 2,
            pointRadius: 0,
            pointHitRadius: 8,
            pointHoverRadius: 4,
            pointHoverBackgroundColor: colorFromHash(at.type),
            tension: 0.3,
            fill: false,
            _attackType: at.type,
        }));

        // Destroy previous instance
        if (attackTrendsChart) {
            attackTrendsChart.destroy();
        }

        const ctx = canvas.getContext('2d');
        attackTrendsChart = new Chart(ctx, {
            type: 'line',
            data: { labels: shortLabels, datasets: datasets },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: {
                    mode: 'index',
                    intersect: false,
                },
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#c9d1d9',
                            font: { size: 11, weight: '500', family: "'Segoe UI', Tahoma, Geneva, Verdana" },
                            padding: 12,
                            usePointStyle: true,
                            pointStyle: 'line',
                        },
                        onClick: function(e, legendItem, legend) {
                            // Default toggle behavior
                            const index = legendItem.datasetIndex;
                            const ci = legend.chart;
                            const meta = ci.getDatasetMeta(index);
                            meta.hidden = meta.hidden === null ? !ci.data.datasets[index].hidden : null;
                            ci.update();

                            // Filter the attacks table by clicking the attack type name
                            const attackType = ci.data.datasets[index]._attackType;
                            filterAttackTableByType(attackType);
                        }
                    },
                    tooltip: {
                        enabled: true,
                        backgroundColor: 'rgba(22, 27, 34, 0.95)',
                        titleColor: '#58a6ff',
                        bodyColor: '#c9d1d9',
                        borderColor: '#30363d',
                        borderWidth: 1,
                        padding: 10,
                        titleFont: { size: 12, weight: 'bold' },
                        bodyFont: { size: 11 },
                        callbacks: {
                            label: function(context) {
                                return `${context.dataset._attackType}: ${context.parsed.y}`;
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        ticks: {
                            color: '#8b949e',
                            font: { size: 10 },
                            maxRotation: 0,
                            autoSkip: true,
                            maxTicksLimit: 15,
                        },
                        grid: { color: 'rgba(48, 54, 61, 0.3)' },
                    },
                    y: {
                        beginAtZero: true,
                        ticks: {
                            color: '#8b949e',
                            font: { size: 10 },
                            precision: 0,
                        },
                        grid: { color: 'rgba(48, 54, 61, 0.3)' },
                    }
                },
                animation: { enabled: false },
            }
        });

    } catch (err) {
        console.error('Error loading attack trends chart:', err);
    }
}

/** Active attack type filter (null = show all) */
let _activeAttackTypeFilter = null;

/**
 * Filter the Detected Attack Types table by a specific attack type.
 * Clicking the same type again clears the filter.
 */
function filterAttackTableByType(attackType) {
    const DASHBOARD_PATH = window.__DASHBOARD_PATH__ || '';
    const container = document.getElementById('attacks-htmx-container');
    if (!container) return;

    if (_activeAttackTypeFilter === attackType) {
        // Clear filter
        _activeAttackTypeFilter = null;
        htmx.ajax('GET', DASHBOARD_PATH + '/htmx/attacks?page=1', { target: container, swap: 'innerHTML' });
    } else {
        // Apply filter
        _activeAttackTypeFilter = attackType;
        htmx.ajax('GET', DASHBOARD_PATH + '/htmx/attacks?page=1&attack_type_filter=' + encodeURIComponent(attackType), { target: container, swap: 'innerHTML' });
    }

    // Update legend styling to show active filter
    updateTrendsLegendHighlight();
}

function updateTrendsLegendHighlight() {
    if (!attackTrendsChart) return;
    // Chart.js will re-render legend on next update; the visual cue
    // is the dataset toggle (hidden/visible) which already happens in onClick
}
