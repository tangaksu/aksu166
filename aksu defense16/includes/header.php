<?php
// aksu defense - 头部安全防护（智能增强版，融合主流互联网最佳实践）
// 参考OWASP、安全头大数据、主流浏览器与WordPress安全建议
if (!defined('ABSPATH')) exit;

function aksu_set_security_headers() {
    // 防止页面被嵌入iframe，防御点击劫持
    header('X-Frame-Options: SAMEORIGIN');
    // 防止类型嗅探
    header('X-Content-Type-Options: nosniff');
    // 防止跨站脚本攻击（XSS）老旧浏览器兼容
    header('X-XSS-Protection: 1; mode=block');
    // 限制Referrer信息
    header('Referrer-Policy: strict-origin-when-cross-origin');
    // 强制HTTPS安全传输
    header('Strict-Transport-Security: max-age=15552000; includeSubDomains; preload');
    // 内容安全策略（CSP），防御XSS/数据注入/部分第三方脚本，适度兼容WordPress生态
    header("Content-Security-Policy: default-src 'self'; img-src * data:; script-src 'self' 'unsafe-inline' 'unsafe-eval' *.google-analytics.com; style-src 'self' 'unsafe-inline'; font-src 'self' data:; frame-ancestors 'self'; object-src 'none'; base-uri 'self'; form-action 'self';");
    // 防止浏览器自动下载文件而非展示
    header("X-Download-Options: noopen");
    // 防止IE执行文件下载
    header("X-Permitted-Cross-Domain-Policies: none");
    // 防止跨站请求伪造（部分支持）
    header("Cross-Origin-Opener-Policy: same-origin");
    header("Cross-Origin-Resource-Policy: same-origin");
    header("Cross-Origin-Embedder-Policy: require-corp");
    // 兼容WordPress、WooCommerce、REST API、站点地图等常见插件
    // 如后台或API接口有特殊需求，可在这里做条件兼容调整
}
add_action('send_headers', 'aksu_set_security_headers', 20);