<?php
/*
Plugin Name: aksu defense15
Description: 轻量级 WordPress 网站安全防火墙，集 CC、防注入、扫描拦截、黑白名单、日志等于一体。
Version: 2.00
Author: aksu
Author URI: https://www.smtsmt.com
Text Domain: aksu-defense
Domain Path: /languages
*/

if (!defined('ABSPATH')) exit;

// ========== 安装与卸载 ==========
require_once __DIR__ . '/includes/install.php';
register_activation_hook(__FILE__, 'aksu_defense_install');

// ========== 加载核心模块 ==========
foreach ([
    'firewall', 'iplist', 'bt', 'cc', 'cookie', 'header', 'useragent',
    'injection', 'scan', 'uri', 'upload', 'filemonitor', 'log'
] as $inc) {
    $inc_file = __DIR__ . "/includes/{$inc}.php";
    if (file_exists($inc_file)) require_once $inc_file;
}

// ========== 全局IP黑白名单校验，保证所有请求都先经过IP判断 ==========
if (function_exists('wpss_iplist_defend')) {
    add_action('init', 'wpss_iplist_defend', 0); // 优先级0，确保最早执行
}

// ========== 后台菜单 ==========
add_action('admin_menu', function () {
    // 设置为99，显示在菜单最底部
    $menu_position = 99;
    add_menu_page(
        '安全防御',
        '安全防御',
        'manage_options',
        'aksu_dashboard',
        'aksu_dashboard_page',
        'dashicons-shield-alt',
        $menu_position
    );
    add_submenu_page('aksu_dashboard', '防火墙规则', '防火墙规则', 'manage_options', 'aksu_firewall', 'aksu_firewall_settings_page');
    add_submenu_page('aksu_dashboard', '安全日志', '安全日志', 'manage_options', 'aksu_logs', 'aksu_logs_page');
    add_submenu_page('aksu_dashboard', '插件设置', '插件设置', 'manage_options', 'aksu_settings', 'aksu_settings_page');
}, 100);

// ========== 加载后台页面 ==========
foreach([
    'dashboard-page', 'firewall-settings-page', 'logs-page', 'settings-page'
] as $admin_page) {
    $admin_file = __DIR__ . "/admin/{$admin_page}.php";
    if (file_exists($admin_file)) require_once $admin_file;
}

// ========== 加载样式与脚本 ==========
add_action('admin_enqueue_scripts', function ($hook) {
    if (strpos($hook, 'aksu') !== false) {
        wp_enqueue_style('aksu-defense-admin', plugins_url('assets/admin.css', __FILE__), [], '1.1');
        wp_enqueue_script('aksu-defense-admin', plugins_url('assets/admin.js', __FILE__), [], '1.1', true);
    }
});

// ========== 语言包加载（init钩子） ==========
add_action('init', function () {
    load_plugin_textdomain('aksu-defense', false, dirname(plugin_basename(__FILE__)) . '/languages');
});

// ========== 文件监控计划任务 ==========
if (!wp_next_scheduled('aksu_filemonitor_snapshot')) {
    wp_schedule_event(time(), 'hourly', 'aksu_filemonitor_snapshot');
}
add_action('aksu_filemonitor_snapshot', 'wpss_filemonitor_save_snapshot');

// ========== 日志自动清理任务 ==========
if (!wp_next_scheduled('aksu_log_cleanup')) {
    wp_schedule_event(time(), 'daily', 'aksu_log_cleanup');
}
add_action('aksu_log_cleanup', function() {
    global $wpdb;
    $table = $wpdb->prefix . 'wpss_logs';
    $days = intval(get_option('wpss_log_retention_days', 30));
    $days = $days > 0 ? $days : 30;
    // 检查表存在再清理
    if ($wpdb->get_var("SHOW TABLES LIKE '$table'") == $table) {
        $wpdb->query($wpdb->prepare("DELETE FROM $table WHERE time < DATE_SUB(NOW(), INTERVAL %d DAY)", $days));
    }
});