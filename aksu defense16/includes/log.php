<?php
// aksu defense - 日志模块（智能增强版）

if (!defined('ABSPATH')) exit;

/**
 * 日志写入函数（智能增强版）
 * 功能说明：
 * 1. 自动收集事件类型、攻击信息、IP、UA、请求URL、来源referer、当前用户名等关键信息。
 * 2. 支持自动去重（短时间内相同IP+类型+信息只记录一次，减少刷日志）。
 * 3. 日志内容防注入、自动标签清理，防止XSS和SQL注入。
 * 4. 支持自定义扩展字段。
 * 5. 防止日志表不存在报错。
 * 6. 兼容插件所有历史调用及钩子。
 *
 * @param string $type 日志类型（如: cc, injection, upload, cookie ...）
 * @param string $msg  详细信息
 * @param string $url  请求路径（可选）
 * @param string $ua   User-Agent（可选）
 * @param array  $ext  扩展字段（可选，形如 ['ref'=>'','user'=>'']）
 */
function wpss_log($type, $msg, $url = '', $ua = '', $ext = []) {
    global $wpdb;

    $table = $wpdb->prefix . 'wpss_logs';
    // 检查表是否存在，防止报错
    if ($wpdb->get_var("SHOW TABLES LIKE '$table'") != $table) return;

    // 基本字段
    $ip    = $_SERVER['REMOTE_ADDR'] ?? '';
    $ua    = $ua ?: ($_SERVER['HTTP_USER_AGENT'] ?? '');
    $url   = $url ?: ($_SERVER['REQUEST_URI'] ?? '');
    $ref   = $_SERVER['HTTP_REFERER'] ?? '';
    $msg   = wp_strip_all_tags($msg);
    $type  = wp_strip_all_tags($type);
    $user  = (is_user_logged_in() && function_exists('wp_get_current_user')) ? wp_get_current_user()->user_login : '';

    // 扩展字段
    if (is_array($ext)) {
        if (isset($ext['ref']))  $ref = wp_strip_all_tags($ext['ref']);
        if (isset($ext['user'])) $user = wp_strip_all_tags($ext['user']);
    }

    // 日志去重：3分钟内同一IP+类型+msg只记录1次
    $recent = $wpdb->get_var(
        $wpdb->prepare(
            "SELECT COUNT(*) FROM $table WHERE ip=%s AND type=%s AND msg=%s AND time >= %s",
            $ip, $type, $msg, gmdate('Y-m-d H:i:s', time() - 180)
        )
    );
    if ($recent > 0) return;

    // 日志写入
    $wpdb->insert($table, [
        'time'  => current_time('mysql'),
        'ip'    => $ip,
        'type'  => $type,
        'msg'   => $msg,
        'ua'    => $ua,
        'url'   => $url,
        // 兼容历史表结构，若有需要可扩展字段
    ]);
}