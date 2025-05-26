<?php
if (!defined('ABSPATH')) exit;

function aksu_defense_install() {
    global $wpdb;
    $table = $wpdb->prefix . 'wpss_logs';
    $charset_collate = $wpdb->get_charset_collate();
    $sql = "CREATE TABLE IF NOT EXISTS `$table` (
        `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
        `ip` varchar(48) NOT NULL DEFAULT '',
        `type` varchar(32) NOT NULL DEFAULT '',
        `msg` text,
        `ua` varchar(255) NOT NULL DEFAULT '',
        `url` varchar(400) NOT NULL DEFAULT '',
        `time` datetime NOT NULL,
        PRIMARY KEY (`id`)
    ) $charset_collate;";
    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    dbDelta($sql);
}