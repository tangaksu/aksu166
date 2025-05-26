<?php
// aksu defense - Cookie注入防护模块
if (!defined('ABSPATH')) exit;

if (!function_exists('aksu_cookie_defend')) {
    function aksu_cookie_defend() {
        // 管理员豁免：已登录且为管理员账号直接放行
        if (function_exists('is_user_logged_in') && function_exists('current_user_can')) {
            if (is_user_logged_in() && current_user_can('manage_options')) return;
        }

        if (!get_option('wpss_fw_cookie_status', 1)) return;

        // 大数据增强版Cookie注入黑名单规则
        $patterns = [
            // XSS
            '/<\s*script/i',
            '/javascript:/i',
            '/onerror\s*=/i',
            '/onload\s*=/i',
            // SQL注入
            '/\bselect\b/i',
            '/\binsert\b/i',
            '/\bupdate\b/i',
            '/\bdelete\b/i',
            '/\bdrop\b/i',
            '/\bunion\b/i',
            '/\bfrom\b/i',
            '/\bwhere\b/i',
            '/\boutfile\b/i',
            '/\bconcat\b/i',
            '/\bload_file\b/i',
            '/\bsleep\s*\(/i',
            '/\bbenchmark\s*\(/i',
            '/\bor\s+1=1\b/i',
            '/\band\s+1=1\b/i',
            // 命令执行/代码执行
            '/base64_decode\s*\(/i',
            '/eval\s*\(/i',
            '/system\s*\(/i',
            '/exec\s*\(/i',
            '/passthru\s*\(/i',
            '/shell_exec\s*\(/i',
            '/phpinfo\s*\(/i',
            // 路径穿越/敏感文件
            '/\.\.\//',
            '/\/etc\/passwd/i',
            '/cmd\.exe/i',
            '/\/bin\/sh/i',
            // 其他危险符号
            '/[\'\";`#]/',
            '/(--|#)/',
            '/\|\|/',
            '/&&/',
        ];

        foreach ($_COOKIE as $k => $v) {
            if (is_array($v)) $v = join(',', $v);
            foreach ($patterns as $pattern) {
                if (preg_match($pattern, $v)) {
                    if (function_exists('wpss_log')) wpss_log('cookie', "Cookie注入拦截: $k=$v");
                    aksu_defense_die('Cookie注入拦截，危险内容已被阻止', null, [], 'cookie');
                }
            }
        }
    }
    add_action('init', 'aksu_cookie_defend', 4);
}