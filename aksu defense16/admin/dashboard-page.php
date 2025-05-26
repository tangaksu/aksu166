<?php
if (!defined('ABSPATH')) exit;

// 仪表盘页面
function aksu_dashboard_page() {
    global $wpdb;
    $table = $wpdb->prefix . 'wpss_logs';

    // 统计类型，加入 firewall
    $firewall_types = [
        'CC攻击防御'        => 'cc',
        'SQL/XSS注入拦截'   => 'injection',
        '恶意User-Agent拦截' => 'useragent',
        'UA黑名单拦截'       => 'useragent_blacklist',
        '敏感路径扫描拦截'   => 'scan',
        'Cookie注入拦截'    => 'cookie',
        '文件上传拦截'      => 'upload',
        'URI规则拦截'      => 'uri',
        '防火墙拦截'        => 'firewall'
    ];

    // 分项统计
    $counts = [];
    foreach ($firewall_types as $label => $type) {
        $counts[$type] = (int)$wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM $table WHERE type=%s", $type));
    }

    // 只统计主要8项 type（即分项全部 type），总数和各项合计一致
    $total_logs = (int)$wpdb->get_var(
        "SELECT COUNT(*) FROM $table WHERE type IN ('cc','injection','useragent','useragent_blacklist','scan','cookie','upload','uri','firewall')"
    );

    // 今日拦截（只统计主要 type + firewall）
    $blocked_today = (int)$wpdb->get_var($wpdb->prepare(
        "SELECT COUNT(*) FROM $table WHERE DATE(time) = %s AND type IN ('cc','injection','useragent','useragent_blacklist','scan','cookie','upload','uri','firewall')",
        current_time('Y-m-d')
    ));

    // 累计封禁IP
    $ip_blocked = (int)$wpdb->get_var("SELECT COUNT(DISTINCT ip) FROM $table WHERE type = 'ipblock'");

    // 近7天拦截趋势（只统计主要 type + firewall），采用WP时区，保证今天必然被统计
    $trend_labels = [];
    $trend_data = [];
    $timezone = wp_timezone(); // WordPress 5.3+ 支持
    for ($i = 6; $i >= 0; $i--) {
        $dt = new DateTime('now', $timezone);
        $dt->modify("-{$i} days");
        $d = $dt->format('Y-m-d');
        $count = (int)$wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM $table WHERE DATE(time) = %s AND type IN ('cc','injection','useragent','useragent_blacklist','scan','cookie','upload','uri','firewall')",
            $d
        ));
        $trend_labels[] = $dt->format('m-d');
        $trend_data[] = $count;
    }

    // 近24小时高频攻击IP（只统计主要 type + firewall）
    $since = date('Y-m-d H:i:s', strtotime('-24 hours'));
    $high_freq_ips = $wpdb->get_results($wpdb->prepare(
        "SELECT ip, COUNT(*) as cnt FROM $table WHERE time > %s AND type IN ('cc','injection','useragent','useragent_blacklist','scan','cookie','upload','uri','firewall') AND ip <> '' GROUP BY ip ORDER BY cnt DESC LIMIT 7",
        $since
    ));

    ?>
    <div class="wrap">
        <h1>安全防御仪表盘</h1>
        <div style="display:flex;gap:30px;margin:25px 0;flex-wrap:wrap;">
            <div class="wpss-card">
                <h2><?php echo esc_html($total_logs); ?></h2>
                <p>拦截总数</p>
            </div>
            <div class="wpss-card">
                <h2><?php echo esc_html($blocked_today); ?></h2>
                <p>今日拦截</p>
            </div>
            <div class="wpss-card">
                <h2><?php echo esc_html($ip_blocked); ?></h2>
                <p>累计封禁IP</p>
            </div>
        </div>

        <h2 style="margin-top:30px;">各防火墙分项拦截统计</h2>
        <div style="display:flex;gap:22px;flex-wrap:wrap;margin-bottom:30px;">
            <?php foreach ($firewall_types as $label => $type): ?>
                <div class="wpss-card" style="min-width:180px;">
                    <h2><?php echo esc_html($counts[$type]); ?></h2>
                    <p><?php echo esc_html($label); ?></p>
                </div>
            <?php endforeach; ?>
        </div>

        <style>
        .wpss-card { background:#fff; border:1px solid #eee; border-radius:6px; box-shadow:0 1px 3px #ddd; display:inline-block; min-width:150px; text-align:center; padding:20px 30px;}
        .wpss-card h2 { margin:0 0 10px 0; font-size:2rem; }

        .wpss-flex-row { display: flex; gap: 24px; margin-bottom: 24px; }
        .wpss-block-half { flex: 1 1 0; background:#fff; border:1px solid #eee; border-radius:6px; box-shadow:0 1px 3px #ddd; padding:20px 24px; display:flex; flex-direction:column; justify-content:space-between; min-width:0; }

        .wpss-block-half h3 { margin-top: 0; font-size: 1.15rem; }
        .wpss-trend-wrap { height: 320px; }
        .wpss-ip-list-table { width: 100%; border-collapse: collapse; }
        .wpss-ip-list-table th, .wpss-ip-list-table td { border: 1px solid #eee; padding: 8px 6px; text-align: left; }
        .wpss-ip-list-table th { background: #f9fafb; }
        </style>

        <div class="wpss-flex-row">
            <div class="wpss-block-half">
                <h3>近7天拦截趋势</h3>
                <div class="wpss-trend-wrap">
                    <canvas id="wpssTrendChart" width="100%" height="300"></canvas>
                </div>
            </div>
            <div class="wpss-block-half">
                <h3>近24小时高频攻击IP（Top 7）</h3>
                <table class="wpss-ip-list-table">
                    <thead>
                        <tr>
                            <th>排名</th>
                            <th>IP地址</th>
                            <th>拦截次数</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if ($high_freq_ips): $rank = 1; foreach ($high_freq_ips as $row): ?>
                        <tr>
                            <td><?php echo $rank++; ?></td>
                            <td><?php echo esc_html($row->ip); ?></td>
                            <td><?php echo esc_html($row->cnt); ?></td>
                        </tr>
                        <?php endforeach; else: ?>
                        <tr><td colspan="3">暂无数据</td></tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <script>
        document.addEventListener('DOMContentLoaded', function() {
            var ctx = document.getElementById('wpssTrendChart').getContext('2d');
            var chart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: <?php echo json_encode($trend_labels); ?>,
                    datasets: [{
                        label: '拦截次数',
                        data: <?php echo json_encode($trend_data); ?>,
                        fill: true,
                        backgroundColor: 'rgba(54, 162, 235, 0.08)',
                        borderColor: 'rgba(54, 162, 235, 1)',
                        borderWidth: 2,
                        pointRadius: 4,
                        pointBackgroundColor: 'rgba(54, 162, 235, 1)',
                        tension: 0.25
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false }
                    },
                    scales: {
                        x: { grid: { display: false } },
                        y: {
                            beginAtZero: true,
                            grid: { color: "#f4f4f4" },
                            ticks: { precision: 0 }
                        }
                    }
                }
            });
        });
        </script>
    </div>
    <?php
}