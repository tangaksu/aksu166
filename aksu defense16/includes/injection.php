<?php
// aksu defense - SQL/XSS注入拦截模块
if (!defined('ABSPATH')) exit;

function aksu_injection_defend() {
    // 管理员豁免：已登录且为管理员账号直接放行
    if (function_exists('is_user_logged_in') && function_exists('current_user_can')) {
        if (is_user_logged_in() && current_user_can('manage_options')) return;
    }

    if (!get_option('wpss_fw_injection_status', 1)) return;

    // 合并所有请求参数
    $params = array_merge($_GET, $_POST, $_COOKIE);
    $all = '';
    foreach ($params as $k => $v) {
        if (is_array($v)) $v = implode(',', $v);
        $all .= $k . '=' . $v . ' ';
    }

    // SQL注入高风险特征
    $sql_rules = [
        // 基础符号和注释
        '/(?:\%27)|(?:\')|(?:\-\-)|(?:\%23)|(#)/i',
        '/\/\*.*\*\//s',
        // 常见SQL关键词和函数
        '/\b(select|update|delete|insert|drop|create|alter|truncate|replace|handler|load|grant|revoke|union|into|outfile|dumpfile|information_schema|sleep|benchmark|char|declare|cast|convert|extractvalue|updatexml|floor|rand)\b/i',
        // 逻辑绕过
        '/(\b(and|or)\b\s*?(=|>|<|in|like|between)|\b(1=1|1=2|0=0|0=1)\b)/i',
        '/\bunion\b.*\bselect\b/i',
        '/\bselect\b.*\bfrom\b/i',
        '/\bwhere\b.*(\d+\s*=\s*\d+)/i',
        '/information_schema|mysql\.|sys\.|performance_schema/i',
        '/(?:sleep|benchmark)\s*\(/i',
        '/(?:order|group)\s+by\s+\d+/i',
        '/@@[a-z_]+/i',
        '/0x[0-9a-f]{4,}/i',
        '/(?:\bcast\b|\bconvert\b)\s*\(/i',
        '/(?:load_file|outfile|dumpfile)\s*\(/i',
        '/(?:xp_cmdshell|sp_executesql|openrowset)/i'
    ];

    // XSS注入高风险特征
    $xss_rules = [
        '/<\s*script\b[^>]*>.*?<\s*\/\s*script\s*>/is',
        '/<\s*iframe\b[^>]*>/i',
        '/<\s*(img|svg|video|audio|embed|object|math|marquee|input|form|body|style|meta|link|base)\b[^>]*>/i',
        '/on\w+\s*=/i',
        '/(src|href|data)\s*=\s*[\"\']?\s*javascript:/i',
        '/javascript\s*:/i',
        '/vbscript\s*:/i',
        '/data\s*:/i',
        '/document\.(cookie|location|domain)/i',
        '/window\.(location|name)/i',
        '/eval\s*\(/i',
        '/expression\s*\(/i',
        '/setTimeout\s*\(/i',
        '/setInterval\s*\(/i',
        '/Function\s*\(/i',
        '/innerHTML\s*=/i',
        '/<\s*base\b[^>]*>/i',
        '/<\s*meta\b[^>]*http-equiv\s*=\s*[\"\']?refresh/i',
        '/style\s*=\s*[\"\']?expression\(/i',
        '/<\s*svg\b[^>]*on\w+\s*=/i',
        '/<\s*svg\b[^>]*xlink:href\s*=\s*[\"\']?javascript:/i',
        '/<!--.*-->/s'
    ];

    foreach ($sql_rules as $rule) {
        if (preg_match($rule, $all)) {
            if (function_exists('wpss_log')) wpss_log('injection', "SQL注入拦截: $all");
            aksu_defense_die('SQL注入拦截，危险参数已阻止', null, [], 'injection');
        }
    }

    foreach ($xss_rules as $rule) {
        if (preg_match($rule, $all)) {
            if (function_exists('wpss_log')) wpss_log('injection', "XSS注入拦截: $all");
            aksu_defense_die('XSS注入拦截，危险参数已阻止', null, [], 'injection');
        }
    }
}
add_action('init', 'aksu_injection_defend', 2);