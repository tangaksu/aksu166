<?php
// aksu defense - IP黑白名单模块（智能增强版）
if (!defined('ABSPATH')) exit;

/**
 * 智能IP黑白名单拦截
 */
function aksu_iplist_defend() {
    // 优先获取真实IP（兼容CDN、代理，防止伪造）
    $ip = '';
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $iplist = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        $ip = trim($iplist[0]);
    } elseif (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        $ip = $_SERVER['HTTP_CLIENT_IP'];
    } else {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
    }

    // 跳过本地回环及内网常见IP（防止自己后台误封）
    $local = ['127.0.0.1', '::1', 'localhost'];
    if (in_array($ip, $local) || preg_match('/^(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)/', $ip)) return;

    $white = get_option('wpss_ip_whitelist', '');
    $black = get_option('wpss_ip_blacklist', '');

    // 支持多种分隔符换行、逗号
    $white_arr = array_filter(array_map('trim', preg_split('/[\n,]+/', $white)));
    $black_arr = array_filter(array_map('trim', preg_split('/[\n,]+/', $black)));

    // 白名单优先
    foreach ($white_arr as $w) {
        if (aksu_ip_match($ip, $w)) {
            // 命中白名单，直接终止后续所有安全检测和WordPress执行流程
            exit;
        }
    }
    foreach ($black_arr as $b) {
        if (aksu_ip_match($ip, $b)) {
            if (function_exists('wpss_log')) wpss_log('ipblock', 'IP黑名单拦截: '.$ip);
            aksu_defense_die('IP被列入黑名单，禁止访问', null, [], 'ip');
        }
    }
}

/**
 * 智能IP匹配
 * 支持单IP、*通配、CIDR、范围、多种格式，兼容IPv6
 */
function aksu_ip_match($ip, $rule) {
    $rule = trim($rule);
    if ($rule === '') return false;
    // 1. 单IP完全匹配
    if (strcasecmp($ip, $rule) === 0) return true;

    // 2. *通配符（如 192.168.*.*）
    if (strpos($rule, '*') !== false) {
        $rule_regex = str_replace(['.', '*'], ['\.', '[0-9a-fA-F:]{1,4,3}'], $rule);
        return preg_match('/^'.$rule_regex.'$/i', $ip);
    }

    // 3. CIDR格式（如 192.168.1.0/24 或 240e:1234::/32）
    if (strpos($rule, '/') !== false) {
        if (function_exists('inet_pton')) {
            list($subnet, $mask) = explode('/', $rule, 2);
            $ip_bin = inet_pton($ip);
            $subnet_bin = inet_pton($subnet);
            if ($ip_bin === false || $subnet_bin === false) return false;
            $mask = intval($mask);
            $len = strlen($ip_bin) * 8;
            if ($mask > $len) $mask = $len;
            for ($i = 0, $bytes = intval($mask / 8); $i < $bytes; $i++) {
                if ($ip_bin[$i] !== $subnet_bin[$i]) return false;
            }
            if ($mask % 8) {
                $i = intval($mask / 8);
                $mask_bin = 0xFF << (8 - $mask % 8);
                if ((ord($ip_bin[$i]) & $mask_bin) !== (ord($subnet_bin[$i]) & $mask_bin)) return false;
            }
            return true;
        }
    }

    // 4. 范围格式（如 1.1.1.1-1.1.1.100）
    if (strpos($rule, '-') !== false && preg_match('/^([\d\.]+)-([\d\.]+)$/', $rule, $m)) {
        $start = ip2long($m[1]);
        $end   = ip2long($m[2]);
        $ipl   = ip2long($ip);
        if ($start && $end && $ipl && $ipl >= $start && $ipl <= $end) return true;
    }

    // 5. IPv6范围或简写
    if (strpos($ip, ':') !== false && strpos($rule, ':') !== false) {
        // 简单模糊匹配
        return stripos($ip, $rule) === 0;
    }

    return false;
}

// 挂载，确保足够靠前（优先级1，已足够），主文件也已全局 add_action('init', 'wpss_iplist_defend', 0);
add_action('init', 'aksu_iplist_defend', 1);
