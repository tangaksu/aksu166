<?php
// aksu defense - 防火墙核心函数（智能增强版）
// 参考主流WAF防护、WordPress安全最佳实践，兼容插件所有拦截与钩子

if (!defined('ABSPATH')) exit;

/**
 * 智能防火墙拦截终止函数
 * @param string $msg 响应体内容（给用户/攻击者的提示）
 * @param int|null $code HTTP状态码，优先使用传入的，默认自动根据后台设置（400/403）
 * @param array $extra_headers 可扩展自定义响应头
 * @param string $scene 可选，指定拦截场景，如 cc/injection/scan/upload/cookie/useragent/uri/custom，自动读取对应option
 * @return void
 */
function aksu_defense_die($msg = 'Access Denied', $code = null, $extra_headers = [], $scene = '') {
    // 防护项目名称映射
    $scene_names = [
        'cc'         => 'CC防护',
        'injection'  => 'SQL/XSS注入防护',
        'useragent'  => 'User-Agent防护',
        'scan'       => '敏感路径扫描防护',
        'cookie'     => 'Cookie注入防护',
        'upload'     => '文件上传防护',
        'php_script' => 'PHP脚本上传防护',
        'uri'        => 'URI规则防护',
        'uri_custom' => '自定义URI规则防护',
        ''           => '智能防火墙'
    ];
    $scene_name = isset($scene_names[$scene]) ? $scene_names[$scene] : $scene;

    // 状态码自动判定（与后台设置同步）
    if (is_null($code) || !in_array($code, [400, 403])) {
        $scene_option_map = [
            'cc'         => 'wpss_fw_cc_code',
            'injection'  => 'wpss_fw_injection_code',
            'useragent'  => 'wpss_fw_useragent_code',
            'scan'       => 'wpss_fw_scan_code',
            'cookie'     => 'wpss_fw_cookie_code',
            'upload'     => 'wpss_fw_upload_code',
            'php_script' => 'wpss_fw_php_script_code',
            'uri'        => 'wpss_fw_uri_code',
            'uri_custom' => 'wpss_fw_uri_custom_code',
        ];
        if ($scene && isset($scene_option_map[$scene])) {
            $opt = get_option($scene_option_map[$scene], 403);
            $code = (in_array(intval($opt), [400,403]) ? intval($opt) : 403);
        } else {
            $code = 403; // 默认
        }
    }

    status_header($code);
    header('Content-Type: text/html; charset=utf-8');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('X-XSS-Protection: 1; mode=block');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: 0');
    if (is_array($extra_headers)) {
        foreach ($extra_headers as $k => $v) {
            header("$k: $v");
        }
    }
    header('X-Aksu-Firewall: Blocked');

    // 日志写入已移除，防止重复记录
    // if (function_exists('wpss_log') && !defined('AKSU_DEFENSE_DIE_LOGGED')) {
    //     define('AKSU_DEFENSE_DIE_LOGGED', 1);
    //     $ip = $_SERVER['REMOTE_ADDR'] ?? '';
    //     $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
    //     $url = $_SERVER['REQUEST_URI'] ?? '';
    //     $referer = $_SERVER['HTTP_REFERER'] ?? '';
    //     $type = 'firewall';
    //     $info = "拦截: {$msg} | IP: {$ip} | UA: {$ua} | URL: {$url} | REF: {$referer} | 项目: {$scene_name}";
    //     wpss_log($type, $info, $url, $ua);
    // }

    // 输出内容
    // 1. 如果有自定义响应体，支持占位符{scene}或{防护项目}
    if ($code === 400) {
        $custom400 = get_option('wpss_resp_html_400', '');
        if (!empty($custom400)) {
            $content = str_replace(['{scene}', '{防护项目}'], $scene_name, $custom400);
            echo $content;
            exit;
        }
    }
    if ($code === 403) {
        $custom403 = get_option('wpss_resp_html_403', '');
        if (!empty($custom403)) {
            $content = str_replace(['{scene}', '{防护项目}'], $scene_name, $custom403);
            echo $content;
            exit;
        }
    }

    // 2. 默认HTML样式输出
    $html = "<div style=\"max-width:480px;margin:60px auto;padding:32px 24px;background:#fff;border:1px solid #eee;border-radius:8px;box-shadow:0 2px 8px #eee;color:#222;font-size:16px;text-align:center;\">";
    $html .= "<h2 style=\"color:#E53935;margin-bottom:24px;\">访问被防火墙拦截</h2>";
    $html .= "<div style=\"margin-bottom:18px;\"><strong>拦截项目：</strong><span style=\"color:#1565c0;\">{$scene_name}</span></div>";
    $html .= "<div style=\"margin-bottom:24px;\">";
    $html .= $msg ? htmlspecialchars($msg) : "您的访问行为被防火墙拦截，如有疑问请联系网站管理员。";
    $html .= "</div>";
    $html .= "<div style=\"color:#888;font-size:14px;\">Powered by <b>AKSU智能防火墙</b></div>";
    $html .= "</div>";

    echo $html;
    exit;
}