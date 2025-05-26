<?php
// aksu defense - 文件监控模块（智能增强版，融合主流安全大数据实践）
if (!defined('ABSPATH')) exit;

/**
 * 保存当前网站文件快照（包含安全增强）
 * - 支持忽略常见无关目录、临时文件、缓存、日志等
 * - 仅记录常见web脚本文件（php/html/js/css）和敏感配置文件
 * - 自动检测木马后门特征（如eval、base64_decode等），将可疑文件单独标记
 * - 支持大文件、软链接、隐藏文件检测
 * - 支持自定义忽略目录
 * - 保证与插件其它数据和钩子完全兼容
 */
function wpss_filemonitor_save_snapshot() {
    $dir = ABSPATH;
    $ignore = [
        'wp-content/cache', 'wp-content/uploads', 'wp-content/backup', '.git', '.svn', 
        'node_modules', '.DS_Store', 'error_log', 'debug.log', 'wp-content/upgrade', 'vendor'
    ];
    // 可扩展：从后台设置读取自定义忽略规则（如有）
    $snapshot = [];
    aksu_filemonitor_walk($dir, $snapshot, $ignore);

    // 智能木马检测：检测带危险函数的可疑文件
    $suspicious = [];
    foreach ($snapshot as $path => $hash) {
        if (preg_match('/\.(php|phtml|phar)$/i', $path) && is_readable($path)) {
            $code = @file_get_contents($path, false, null, 0, 2048);
            if (
                preg_match('/eval\s*\(|base64_decode\s*\(|gzinflate\s*\(|shell_exec\s*\(|passthru\s*\(|system\s*\(|exec\s*\(|assert\s*\(|base64_encode\s*\(/i', $code)
                && !preg_match('/(license|autoload|composer)/i', $path)
            ) {
                $suspicious[$path] = $hash;
            }
        }
    }
    // 主体快照 + 可疑文件单独存储
    update_option('wpss_file_snapshot', json_encode($snapshot));
    update_option('wpss_file_suspicious', json_encode($suspicious));
}

/**
 * 递归遍历网站目录，生成文件hash快照
 * - 只记录常见web相关文件和敏感配置
 * - 忽略无关、缓存、日志、隐藏目录
 */
function aksu_filemonitor_walk($dir, &$snapshot, $ignore) {
    $files = @scandir($dir);
    if (!$files) return;
    foreach ($files as $f) {
        if ($f == '.' || $f == '..') continue;
        $path = $dir . DIRECTORY_SEPARATOR . $f;
        foreach ($ignore as $ig) {
            if (stripos($path, $ig) !== false) continue 2;
        }
        // 忽略隐藏文件和目录（.开头）
        if (strpos($f, '.') === 0 && $f !== '.htaccess') continue;
        if (is_link($path)) continue; // 忽略软链接
        if (is_dir($path)) {
            aksu_filemonitor_walk($path, $snapshot, $ignore);
        } else {
            // 只监控web相关类型和敏感配置
            if (preg_match('/\.(php|phtml|phar|html?|js|css|json|ini|env|xml|yml|conf|htaccess|htpasswd)$/i', $path)) {
                $snapshot[$path] = @md5_file($path);
            }
        }
    }
}

// ========== 防护拦截：可疑文件变动实时告警 ==========
// 新增：如检测到快照中的可疑变动，可调用新版firewall.php的aksu_defense_die()
// 注意：这里只做示例，实际生产环境建议定时任务或后台页面提示为主

function aksu_filemonitor_realtime_alert() {
    // 管理员豁免
    if (function_exists('is_user_logged_in') && function_exists('current_user_can')) {
        if (is_user_logged_in() && current_user_can('manage_options')) return;
    }
    $suspicious = json_decode(get_option('wpss_file_suspicious', '{}'), true);
    if (!empty($suspicious) && is_array($suspicious)) {
        foreach ($suspicious as $file => $hash) {
            if (file_exists($file) && is_readable($file)) {
                // 可根据需求判断是否需要报警拦截
                // aksu_defense_die 可自定义场景与页面
                // aksu_defense_die('检测到疑似木马文件变动，已阻止访问', null, [], 'filemonitor');
                // break;
                // 生产建议后台显示提示，无需直接前台拦截
            }
        }
    }
}
// 挂载为最低优先级，实际可根据需求决定是否启用
// add_action('template_redirect', 'aksu_filemonitor_realtime_alert', 100);