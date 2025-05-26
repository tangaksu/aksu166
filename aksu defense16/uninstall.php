<?php
// aksu defense - 卸载脚本
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}
global $wpdb;
$table = $wpdb->prefix . 'wpss_logs';
$wpdb->query("DROP TABLE IF EXISTS `$table`");
$options = [
    'wpss_ip_whitelist','wpss_ip_blacklist','wpss_fw_cc_status','wpss_cc_limit','wpss_cc_period','wpss_cc_blocktime',
    'wpss_fw_injection_status','wpss_fw_useragent_status','wpss_fw_scan_status','wpss_fw_cookie_status',
    'wpss_fw_upload_status','wpss_fw_php_script_status','wpss_fw_uri_status','wpss_fw_uri_custom_status',
    'wpss_uri_custom_rules','wpss_admin_email','wpss_file_snapshot','wpss_ua_blacklist','wpss_log_display_count','wpss_log_retention_days'
];
foreach ($options as $opt) delete_option($opt);