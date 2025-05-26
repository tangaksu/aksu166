<?php
// aksu defense - CC攻击防护模块
if (!defined('ABSPATH')) exit;

if (!function_exists('aksu_cc_defend')) {
    function aksu_cc_defend() {
        // 管理员豁免：已登录且为管理员账号直接放行
        if (function_exists('is_user_logged_in') && function_exists('current_user_can')) {
            if (is_user_logged_in() && current_user_can('manage_options')) return;
        }

        // ---- 新增：后台页面豁免CC防护 ----
        if (
            (isset($_SERVER['REQUEST_URI']) && strpos($_SERVER['REQUEST_URI'], '/wp-admin/') === 0)
            || (isset($_SERVER['REQUEST_URI']) && strpos($_SERVER['REQUEST_URI'], '/wp-login.php') !== false)
        ) {
            return;
        }
        // ---- 结束 ----

        if (!get_option('wpss_fw_cc_status', 1)) return;

        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $referer = $_SERVER['HTTP_REFERER'] ?? '';
        $host = $_SERVER['HTTP_HOST'] ?? '';
        $req_uri = $_SERVER['REQUEST_URI'] ?? '';
        $key = 'aksu_cc_' . md5($ip . $host);

        // 配置参数
        $limit = intval(get_option('wpss_cc_limit', 60));     // 单位周期最大请求数
        $period = intval(get_option('wpss_cc_period', 60));   // 统计周期(秒)
        $blocktime = intval(get_option('wpss_cc_blocktime', 1800)); // 封禁时长(秒)

        // 大数据增强：常见CC攻击特征拦截
        $dangerous_ua_patterns = [
            '/curl/i', '/wget/i', '/python-requests/i', '/httpclient/i', '/scrapy/i', '/go-http-client/i', '/lwp::simple/i', '/okhttp/i'
        ];
        $dangerous_uri_patterns = [
            '/(admin|login|wp-login|xmlrpc)\.php/i', // 针对敏感页面的爆破
            '/\?id=\d+/i', '/\?p=\d+/i', // 带有参数的爆破
        ];

        // 1. 检查危险UA特征
        foreach ($dangerous_ua_patterns as $pattern) {
            if (preg_match($pattern, $ua)) {
                if (function_exists('wpss_log')) wpss_log('cc', "可疑UA特征CC拦截: $ip $ua");
                aksu_defense_die('CC攻击检测，疑似恶意请求', null, [], 'cc');
            }
        }
        // 2. 检查URI特征
        foreach ($dangerous_uri_patterns as $pattern) {
            if (preg_match($pattern, $req_uri)) {
                if (function_exists('wpss_log')) wpss_log('cc', "敏感URI特征CC拦截: $ip $req_uri");
                aksu_defense_die('CC攻击检测，疑似恶意请求', null, [], 'cc');
            }
        }

        // 4. 速率限制（原有逻辑）
        $now = time();
        $cc_data = get_transient($key);
        if (!$cc_data) {
            $cc_data = ['start' => $now, 'count' => 1, 'blocked' => 0];
        } else {
            // 已被封禁
            if (!empty($cc_data['blocked']) && $now < $cc_data['blocked']) {
                if (function_exists('wpss_log')) wpss_log('cc', "CC攻击防护，已封锁: $ip");
                aksu_defense_die('CC攻击防护，访问过快已被封锁', null, [], 'cc');
            }
            // 超出统计周期，重置计数
            if ($now - $cc_data['start'] > $period) {
                $cc_data = ['start' => $now, 'count' => 1, 'blocked' => 0];
            } else {
                $cc_data['count']++;
                if ($cc_data['count'] > $limit) {
                    $cc_data['blocked'] = $now + $blocktime;
                    set_transient($key, $cc_data, $blocktime);
                    if (function_exists('wpss_log')) wpss_log('cc', "CC攻击检测，自动封锁: $ip");
                    aksu_defense_die('CC攻击防护，访问过快已被封锁', null, [], 'cc');
                }
            }
        }
        set_transient($key, $cc_data, $period);
    }
    add_action('init', 'aksu_cc_defend', 3);
}