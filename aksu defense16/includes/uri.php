<?php
// aksu defense - URI规则拦截模块
if (!defined('ABSPATH')) exit;

if (!function_exists('aksu_uri_defend')) {
    function aksu_uri_defend() {
        // 管理员豁免：已登录且有插件管理权限直接放行
        if (function_exists('is_admin') && function_exists('is_user_logged_in') && function_exists('current_user_can')) {
            if (is_admin() && is_user_logged_in() && current_user_can('activate_plugins')) {
                return;
            }
        }

        if (!get_option('wpss_fw_uri_status', 1)) return;
        $uri = $_SERVER['REQUEST_URI'] ?? '';

        // 大数据增强：常见攻击型URI或敏感路径正则黑名单
        $dangerous_uri_patterns = [
            // 路径穿越
            '/(\.\.\/|\.\.\\\\|%2e%2e|%2f|%5c)/i',
            '/\x00/', // 空字节注入
            // 常见扫描、探针、后门路径
            '/(phpmyadmin|adminer|wp-config|wp-adminer|\.env|shell\.php|webshell\.php|cmd\.php|info\.php|test\.php|dbadmin|pma|mysql|www\.zip|backup\.zip|setup\.php|install\.php|config\.inc\.php|\.tar|\.tar\.gz|\.rar|\.zip|\.bak|\.swp|\.old|\.backup|\.log|\.bk|\.tmp|\.xz|composer\.json|composer\.lock|package\.json|\.npmrc|docker-compose\.yml|dockerfile|passwd|shadow|\.git|\.svn|\.hg|\.idea|\.vscode|id_rsa|id_dsa|authorized_keys|known_hosts|\.ssh|\.aws|\.azure|wp-admin\/setup-config\.php|wp-admin\/install\.php|wp-admin\/upgrade\.php|admin\.php|login|administrator|webdav)/i',
            // SQL注入特征
            '/(\bselect\b.*\bfrom\b|\binsert\b.*\binto\b|\bupdate\b.*\bset\b|\bdelete\b.*\bfrom\b|\bunion(\s+all)?\b.*\bselect\b)/i',
            '/(\bor\s+1=1\b|\band\s+1=1\b|\bbenchmark\s*\(|\bsleep\s*\()/i',
            // 跨站XSS特征
            '/(<script|onerror\s*=|onload\s*=|javascript:)/i',
            // 命令执行特征
            '/(;|\|\||&&|\bcat\b|\bping\b|\bwhoami\b|\bifconfig\b|\bnetstat\b|\bpasswd\b|\bshutdown\b|\breboot\b)/i',
            // 长度超限（可防止目录暴力遍历）
            '/.{400,}/',
        ];

        foreach ($dangerous_uri_patterns as $pattern) {
            if (preg_match($pattern, $uri)) {
                if (function_exists('wpss_log')) wpss_log('uri', "危险/敏感URI规则拦截: $uri, 规则: $pattern");
                aksu_defense_die('URI规则拦截，访问被阻止', null, [], 'uri');
            }
        }

        // 自定义URI规则
        if (get_option('wpss_fw_uri_custom_status', 0)) {
            $rules = get_option('wpss_uri_custom_rules', '');
            if (!empty($rules)) {
                $lines = explode("\n", $rules);
                foreach ($lines as $ruleline) {
                    $ruleline = trim($ruleline);
                    if ($ruleline === '') continue;

                    // 支持多规则|分割
                    $subrules = explode('|', $ruleline);
                    foreach ($subrules as $rule) {
                        $rule = trim($rule);
                        if ($rule === '') continue;
                        // 判断是否正则（以/开头结尾），否则为字符串
                        if ($rule[0] === '/' && substr($rule, -1) === '/') {
                            if (@preg_match($rule, $uri)) {
                                if (function_exists('wpss_log')) wpss_log('uri', "自定义URI规则拦截(正则): $uri, 规则: $rule");
                                aksu_defense_die('自定义URI规则拦截', null, [], 'uri_custom');
                            }
                        } else {
                            if (stripos($uri, $rule) !== false) {
                                if (function_exists('wpss_log')) wpss_log('uri', "自定义URI规则拦截: $uri, 规则: $rule");
                                aksu_defense_die('自定义URI规则拦截', null, [], 'uri_custom');
                            }
                        }
                    }
                }
            }
        }
    }
    add_action('init', 'aksu_uri_defend', 7);
}