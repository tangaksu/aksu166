<?php
// aksu defense - 恶意User-Agent防御
if (!defined('ABSPATH')) exit;

function aksu_useragent_defend() {
    // 管理员豁免：已登录且为管理员账号直接放行
    if (function_exists('is_user_logged_in') && function_exists('current_user_can')) {
        if (is_user_logged_in() && current_user_can('manage_options')) return;
    }

    if (!get_option('wpss_fw_useragent_status', 1)) return;
    $ua = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';

    // 对所有中国爬虫/spider/bot等放行 Google、Bing
    if (
        stripos($ua, 'spider') !== false ||
        stripos($ua, 'bot') !== false ||
        stripos($ua, 'crawler') !== false ||
        stripos($ua, 'slurp') !== false ||
        stripos($ua, 'archiver') !== false ||
        stripos($ua, 'transcoder') !== false ||
        stripos($ua, 'fetcher') !== false ||
        stripos($ua, 'apex') !== false ||
        stripos($ua, 'baiduspider') !== false ||
        stripos($ua, 'sogou') !== false ||
        stripos($ua, 'sosospider') !== false ||
        stripos($ua, '360spider') !== false ||
        stripos($ua, 'yisouspider') !== false ||
        stripos($ua, 'bytespider') !== false ||
        stripos($ua, 'bingbot') !== false ||
        stripos($ua, 'bingpreview') !== false ||
        stripos($ua, 'google') !== false ||
        stripos($ua, 'toutiao') !== false
    ) {
        return; // 符合放行条件
    }

    // 恶意User-Agent关键字大数据黑名单（不含爬虫相关关键词）
    $malicious_agents = [
        // 常见安全扫描和攻击工具
        'sqlmap', 'acunetix', 'wvs', 'netsparker', 'nikto', 'fimap', 'nmap', 'nessus', 'zaproxy', 'arachni', 'wpscan',
        'havij', 'dirbuster', 'dirb', 'webshag', 'owasp', 'appscan', 'metasploit', 'paros', 'qualys', 'jaeles', 'masscan',
        // 各类脚本/采集工具
        'python-requests', 'curl', 'wget', 'httpclient', 'libwww-perl', 'python-urllib', 'java/', 'Go-http-client', 'okhttp', 'scrapy',
        // 高危特征
        'morfeus', 'scan', 'xss', 'attack', 'exploit', 'sql', 'winhttp',
        'Mozilla/5.0 zgrab', 'ZmEu', 'curl/', 'masscan/', 'Go-http-client/', 'python-requests/', 'WordPress/4.', 'Fuzz', 'WinInet'
    ];

    foreach ($malicious_agents as $badua) {
        if (stripos($ua, $badua) !== false) {
            if (function_exists('wpss_log')) wpss_log('useragent', "恶意User-Agent拦截: $ua");
            aksu_defense_die('恶意User-Agent拦截，禁止访问', null, [], 'useragent');
        }
    }

    // 正则拦截部分特定UA格式
    $regex_agents = [
        '/python\-requests/i',
        '/curl[\s\/]/i',
        '/wget/i',
        '/libwww\-perl/i',
        '/java\//i',
        '/Go\-http\-client/i',
        '/ZmEu/i',
        '/sqlmap/i',
        '/masscan/i',
        '/dirbuster/i',
        '/acunetix/i',
        '/nikto/i',
        '/wpscan/i',
        '/binlar/i',
        '/morfeus/i'
    ];
    foreach ($regex_agents as $reg) {
        if (preg_match($reg, $ua)) {
            if (function_exists('wpss_log')) wpss_log('useragent', "恶意User-Agent正则拦截: $ua");
            aksu_defense_die('恶意User-Agent拦截，禁止访问', null, [], 'useragent');
        }
    }
    // 2. 自定义User-Agent黑名单（支持*通配符和普通关键词）
    $custom = trim(get_option('wpss_ua_blacklist', ''));
    if ($custom) {
        $rules = explode('|', $custom);
        foreach ($rules as $rule) {
            $pattern = trim($rule);
            if ($pattern === '') continue;
            // 智能支持 * 通配符，自动转正则匹配
            $preg = '/^' . str_replace('\*', '.*', preg_quote($pattern, '/')) . '$/i';
            if (preg_match($preg, $ua)) {
                if (function_exists('wpss_log')) wpss_log('useragent_blacklist', "UA黑名单拦截: $ua");
                aksu_defense_die('User-Agent黑名单规则拦截', null, [], 'useragent');
            }
        }
    }
}
add_action('init', 'aksu_useragent_defend', 4);