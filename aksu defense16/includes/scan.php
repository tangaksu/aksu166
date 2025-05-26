<?php
// aksu defense - 敏感路径/扫描行为拦截
if (!defined('ABSPATH')) exit;

function aksu_scan_defend() {
    // 管理员豁免：已登录且为管理员账号直接放行
    if (function_exists('is_user_logged_in') && function_exists('current_user_can')) {
        if (is_user_logged_in() && current_user_can('manage_options')) return;
    }
    if (!get_option('wpss_fw_scan_status', 1)) return;
    $request_uri = strtolower($_SERVER['REQUEST_URI'] ?? '');
    $bad_paths = [
        // 数据库面板、管理工具
        '/phpmyadmin','/adminer','/dbadmin','/pma','/mysql',
        // WP相关文件和备份
        '/wp-config','/wp-config.php','/wp-adminer','/wp-admin/setup-config.php','/wp-admin/install.php','/wp-admin/upgrade.php',
        '/wp-config.php~','/wp-config.php.bak','/wp-config.php.save','/wp-config.php.swp','/wp-config.php.swo','/wp-config.php.swn',
        '/wp-config.bak','/wp-config.old','/wp-config.inc','/wp-config.txt',
        // 备份和压缩包
        '/www.zip','/backup.zip','/backup.sql','/db.sql','/dump.sql','/database.sql',
        '.zip','.tar','.tar.gz','.rar','.tar.bz2','.7z','.bak','.bak1','.backup','.old','.tmp','.swp','.bk','.tar.xz',
        // 环境与配置
        '/.env','.env','.git','.svn','.hg','.DS_Store','web.config','config.php~','config.bak','config.old',
        'composer.lock','composer.json','package.json','.npmrc','.bash_history',
        // 密钥与授权
        'id_rsa','id_dsa','authorized_keys','known_hosts','.ssh/','.aws/','.azure/',
        // 敏感信息/源码/日志
        '.idea','.vscode','docker-compose.yml','dockerfile','proc/self/environ','proc/version','passwd','shadow','/etc/passwd','/etc/shadow',
        // 工具/后门/探针
        '/shell.php','/webshell.php','/cmd.php','/phpinfo.php','/info.php','/test.php','/setup.php',
        // 后台登录与敏感目录（已去除/admin/，可正常使用/wp-admin/）
        '/admin.php', /*'/admin/',*/ '/login/', '/administrator/', '/webdav/',
        // 路径穿越与变种
        '../','..\\','%2e%2e%2f','%2e%2e\\','%252e%252e%252f'
    ];
    foreach ($bad_paths as $path) {
        if (strpos($request_uri, $path) !== false) {
            if (function_exists('wpss_log')) wpss_log('scan', "敏感路径扫描拦截: $request_uri");
            aksu_defense_die('敏感路径访问被拦截', null, [], 'scan');
        }
    }
}
add_action('init', 'aksu_scan_defend', 5);

// 高级敏感路径扫描拦截（补充，管理员豁免）
if (!function_exists('aksu_sensitive_path_defend')) {
    function aksu_sensitive_path_defend() {
        // 管理员豁免：已登录且为管理员账号直接放行
        if (function_exists('is_user_logged_in') && function_exists('current_user_can')) {
            if (is_user_logged_in() && current_user_can('manage_options')) return;
        }
        if (!isset($_SERVER['REQUEST_URI'])) return;
        $uri = strtolower($_SERVER['REQUEST_URI']);
        $sensitive_paths = [
            '.env','.git','.svn','.hg','.DS_Store','web.config','config.php~','config.bak','config.old',
            'wp-config.php~','wp-config.php.bak','wp-config.php.save','wp-config.php.swp','wp-config.php.swo','wp-config.php.swn',
            'wp-config.bak','wp-config.old','wp-config.inc','wp-config.txt',
            'composer.lock','composer.json','package.json','.npmrc','.bash_history',
            'id_rsa','id_dsa','authorized_keys','known_hosts','.ssh/','.aws/','.azure/',
            'backup.sql','db.sql','dump.sql','database.sql','.sql','.bak','.backup','.old','.log',
            '../','..\\','%2e%2e%2f','%2e%2e\\','%252e%252e%252f',
            'phpinfo.php','shell.php','cmd.php','test.php','setup.php',
            'phpmyadmin','pma','mysql','wp-admin/setup-config.php','wp-admin/install.php','wp-admin/upgrade.php',
            'admin.php', /*'admin/',*/ 'login/','administrator/','webdav/',
            '.zip','.tar','.tar.gz','.rar','.swp','~','.tmp','.tar.bz2','.7z','.bak1','.bk','.tar.xz',
            '.idea','.vscode','docker-compose.yml','dockerfile','proc/self/environ','proc/version','passwd','shadow','/etc/passwd','/etc/shadow'
        ];
        foreach ($sensitive_paths as $path) {
            if (strpos($uri, $path) !== false) {
                if (function_exists('wpss_log')) wpss_log('sensitive_path', "敏感路径拦截: $uri");
                aksu_defense_die('敏感路径访问被拦截', null, [], 'scan');
            }
        }
    }
    add_action('init', 'aksu_sensitive_path_defend', 3);
}