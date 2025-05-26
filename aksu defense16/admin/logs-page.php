<?php
if (!defined('ABSPATH')) exit;

// 日志管理页面
function aksu_logs_page() {
    global $wpdb;
    $table = $wpdb->prefix . 'wpss_logs';

    // 清理日志
    if (isset($_POST['wpss_logs_clear']) && check_admin_referer('wpss_logs_clear')) {
        $wpdb->query("TRUNCATE TABLE $table");
        echo '<div class="updated"><p>日志已清空。</p></div>';
    }

    // 导出日志
    if (isset($_POST['wpss_logs_export']) && check_admin_referer('wpss_logs_export')) {
        $logs = $wpdb->get_results("SELECT * FROM $table ORDER BY id DESC");
        header('Content-Type: text/csv');
        header('Content-Disposition: attachment;filename="aksu-defense-logs.csv"');
        echo "序号,时间,IP,类型,信息,UA,请求\n";
        $seq = 1;
        foreach ($logs as $log) {
            echo '"' . $seq++ . '","' . $log->time . '","' . $log->ip . '","' . $log->type . '","' . str_replace('"', '""', $log->msg) . '","' . str_replace('"', '""', $log->ua) . '","' . str_replace('"', '""', $log->url) . '"' . "\n";
        }
        exit;
    }

    // 分页（最多7页，每页30条最新日志）
    $page = max(1, intval($_GET['paged'] ?? 1));
    $per_page = 30;
    $total = (int)$wpdb->get_var("SELECT COUNT(*) FROM $table");
    $pages = min(7, max(1, ceil($total / $per_page)));
    $page = min($page, $pages);
    $offset = ($page - 1) * $per_page;
    $logs = $wpdb->get_results($wpdb->prepare("SELECT * FROM $table ORDER BY id DESC LIMIT %d OFFSET %d", $per_page, $offset));

    // 计算当前页起始序号
    $seq_start = ($page - 1) * $per_page + 1;

    ?>
    <div class="wrap">
        <h1>安全日志</h1>
        <form method="post" style="margin-bottom:16px;display:flex;gap:12px;align-items:center;">
            <?php wp_nonce_field('wpss_logs_export'); ?>
            <button type="submit" class="button" name="wpss_logs_export">导出全部日志</button>
            <?php wp_nonce_field('wpss_logs_clear'); ?>
            <button type="submit" class="button" name="wpss_logs_clear" onclick="return confirm('确定要清空所有日志吗？');">清空全部日志</button>
        </form>
        <style>
        .aksu-logs-table th,
        .aksu-logs-table td {
            padding: 6px 8px;
            text-align: left;
            vertical-align: top;
            word-break: break-all;
        }
        .aksu-logs-table th.id,
        .aksu-logs-table td.id { width: 44px; }
        .aksu-logs-table th.time,
        .aksu-logs-table td.time { width: 110px; }
        .aksu-logs-table th.ip,
        .aksu-logs-table td.ip { width: 110px; }
        .aksu-logs-table th.type,
        .aksu-logs-table td.type { width: 90px; }
        .aksu-logs-table th.msg,
        .aksu-logs-table td.msg { width: 250px; max-width: 320px; }
        .aksu-logs-table th.ua,
        .aksu-logs-table td.ua { width: 260px; max-width: 400px;}
        .aksu-logs-table th.url,
        .aksu-logs-table td.url { width: 130px; }
        @media (max-width: 1100px) {
            .aksu-logs-table th.msg,
            .aksu-logs-table td.msg { width: 180px; max-width: 200px; }
            .aksu-logs-table th.ua,
            .aksu-logs-table td.ua { width: 150px; max-width: 180px;}
        }
        .aksu-logs-desc {
            margin-top:20px;
            color: #888;
            font-size: 0.99rem;
        }
        </style>
        <table class="widefat fixed aksu-logs-table">
            <thead>
                <tr>
                    <th class="id">序号</th>
                    <th class="time">时间</th>
                    <th class="ip">IP</th>
                    <th class="type">类型</th>
                    <th class="msg">信息</th>
                    <th class="ua">UserAgent</th>
                    <th class="url">请求</th>
                </tr>
            </thead>
            <tbody>
            <?php
            if ($logs) {
                $seq = $seq_start;
                foreach ($logs as $log) {
                    echo '<tr>';
                    echo '<td class="id">' . $seq++ . '</td>';
                    echo '<td class="time">' . esc_html($log->time) . '</td>';
                    echo '<td class="ip">' . esc_html($log->ip) . '</td>';
                    echo '<td class="type">' . esc_html($log->type) . '</td>';
                    echo '<td class="msg">' . esc_html($log->msg) . '</td>';
                    echo '<td class="ua">' . esc_html($log->ua) . '</td>';
                    echo '<td class="url">' . esc_html($log->url) . '</td>';
                    echo '</tr>';
                }
            } else {
                echo '<tr><td colspan="7">暂无日志</td></tr>';
            }
            ?>
            </tbody>
        </table>
        <div style="margin:16px 0;">
            <?php
            if ($pages > 1) {
                for ($i = 1; $i <= $pages; $i++) {
                    if ($i == $page) {
                        echo "<span style='padding:4px 10px;background:#2271b1;color:#fff;border-radius:3px;margin-right:5px;'>$i</span>";
                    } else {
                        echo '<a style="padding:4px 10px;border:1px solid #ddd;border-radius:3px;margin-right:5px;" href="'.esc_url(add_query_arg('paged', $i)).'">'.$i.'</a>';
                    }
                }
            }
            ?>
        </div>
        <div class="aksu-logs-desc">
            <strong>日志说明：</strong>
            日志将自动保留最近7天，系统每天会自动清理7天前的所有日志，无需手动设置或干预。
        </div>
    </div>
    <?php
}

// 日志自动清理计划：每天凌晨 02:05 删除7天前的日志
if (!function_exists('aksu_logs_cleanup_schedule')) {
    add_action('wp', function() {
        if (!wp_next_scheduled('aksu_logs_cleanup_event')) {
            wp_schedule_event(strtotime('02:05:00'), 'daily', 'aksu_logs_cleanup_event');
        }
    });

    add_action('aksu_logs_cleanup_event', 'aksu_logs_cleanup_old_logs');
    function aksu_logs_cleanup_old_logs() {
        global $wpdb;
        $table = $wpdb->prefix . 'wpss_logs';
        $seven_days_ago = date('Y-m-d H:i:s', strtotime('-7 days'));
        $wpdb->query($wpdb->prepare("DELETE FROM $table WHERE time < %s", $seven_days_ago));
    }
}