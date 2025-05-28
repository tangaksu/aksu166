<?php
/*
Plugin Name: 智能站点地图
Plugin URI: https://www.smtsmt.com/
Description: 自动生成百度、谷歌等搜索引擎支持的 XML 站点地图，支持自动定时和手动生成，可自定义文章与标签显示数量。
Version: 4.5
Author: aksu
Author URI: https://www.smtsmt.com/
License: GPL2
Text Domain: aksu-sitemap
*/

if (!defined('ABSPATH')) exit;

class Smart_Sitemap_Generator_V2 {

    private $option_name = 'sm_sitemap_settings';
    private $sitemap_file = 'sitemap.xml';

    public function __construct() {
        register_activation_hook(__FILE__, [$this, 'activate']);
        register_deactivation_hook(__FILE__, [$this, 'deactivate']);
        add_action('wp', [$this, 'schedule_events']);
        add_action('sm_daily_sitemap_update', [$this, 'generate_sitemap_file']);
        add_action('admin_menu', [$this, 'add_admin_menu']);
        add_action('admin_init', [$this, 'register_settings']);
        add_filter('plugin_action_links_' . plugin_basename(__FILE__), [$this, 'add_settings_link']);
    }

    public function activate() {
        $this->generate_sitemap_file();
        $this->schedule_events(true);
        flush_rewrite_rules();
    }

    public function deactivate() {
        wp_clear_scheduled_hook('sm_daily_sitemap_update');
        delete_transient('sm_sitemap_cache');
        flush_rewrite_rules();
    }

    public function register_settings() {
        register_setting('sm_sitemap_setting_group', $this->option_name, [
            'type' => 'array',
            'sanitize_callback' => [$this, 'sanitize_options']
        ]);
        add_settings_section('sm_sitemap_section', '', null, 'sm-sitemap-settings');
        add_settings_field('cron_hour', '定时生成时间（小时）', [$this, 'cron_hour_field_html'], 'sm-sitemap-settings', 'sm_sitemap_section');
        add_settings_field('post_limit', '文章列表显示数量', [$this, 'post_limit_field_html'], 'sm-sitemap-settings', 'sm_sitemap_section');
        add_settings_field('tag_limit', '标签列表显示数量', [$this, 'tag_limit_field_html'], 'sm-sitemap-settings', 'sm_sitemap_section');
        // 用标准钩子确保设置变动后刷新定时
        add_action('update_option_' . $this->option_name, [$this, 'settings_updated'], 10, 0);
    }

    public function cron_hour_field_html() {
        $options = get_option($this->option_name);
        $hour = isset($options['cron_hour']) ? intval($options['cron_hour']) : 1;
        echo '<select name="' . esc_attr($this->option_name) . '[cron_hour]" style="width:80px;">';
        for ($i = 0; $i < 24; $i++) {
            printf('<option value="%d"%s>%02d:00</option>', $i, selected($hour, $i, false), $i);
        }
        echo '</select> <span class="description">每天该小时自动生成sitemap（网站本地时区）</span>';
        // 显示下次执行时间
        $next = wp_next_scheduled('sm_daily_sitemap_update');
        if ($next) {
            $dt = new DateTime('@' . $next);
            $dt->setTimezone(wp_timezone());
            echo '<div style="margin-top:4px;color:#1976d2;">下次执行时间：' . esc_html($dt->format('Y-m-d H:i')) . '</div>';
        }
    }

    public function post_limit_field_html() {
        $options = get_option($this->option_name);
        $post_limit = isset($options['post_limit']) ? intval($options['post_limit']) : 3000;
        echo '<input type="number" name="' . esc_attr($this->option_name) . '[post_limit]" value="' . esc_attr($post_limit) . '" min="1" max="10000" style="width:100px;" />';
        echo ' <span class="description">生成sitemap时文章最大数量，默认3000</span>';
    }

    public function tag_limit_field_html() {
        $options = get_option($this->option_name);
        $tag_limit = isset($options['tag_limit']) ? intval($options['tag_limit']) : 500;
        echo '<input type="number" name="' . esc_attr($this->option_name) . '[tag_limit]" value="' . esc_attr($tag_limit) . '" min="1" max="2000" style="width:100px;" />';
        echo ' <span class="description">生成sitemap时标签最大数量，默认500</span>';
    }

    public function sanitize_options($input) {
        $output = [];
        $output['cron_hour'] = isset($input['cron_hour']) ? max(0, min(23, intval($input['cron_hour']))) : 1;
        $output['post_limit'] = isset($input['post_limit']) ? max(1, min(10000, intval($input['post_limit']))) : 3000;
        $output['tag_limit'] = isset($input['tag_limit']) ? max(1, min(2000, intval($input['tag_limit']))) : 500;
        return $output;
    }

    /**
     * 定时任务调度，确保按WP本地时区执行
     */
    public function schedule_events($force = false) {
        $hook = 'sm_daily_sitemap_update';
        // 彻底清理旧的
        wp_clear_scheduled_hook($hook);

        $options = get_option($this->option_name);
        $hour = isset($options['cron_hour']) ? intval($options['cron_hour']) : 1;

        $tz = wp_timezone();
        $now = new DateTime('now', $tz);
        $today_run = new DateTime('today', $tz);
        $today_run->setTime($hour, 0, 0);
        if ($today_run < $now) {
            $today_run->modify('+1 day');
        }
        $first_run = $today_run->getTimestamp();

        // 重新注册
        wp_schedule_event($first_run, 'daily', $hook);
    }

    public function settings_updated() {
        $this->schedule_events(true);
    }

    /**
     * 生成 sitemap 文件
     */
    public function generate_sitemap_file() {
        if (!is_writable(ABSPATH)) return false;
        delete_transient('sm_sitemap_cache');
        $content = $this->generate_sitemap();
        $file_path = ABSPATH . $this->sitemap_file;
        return file_put_contents($file_path, $content, LOCK_EX) !== false;
    }

    /**
     * 生成 sitemap 内容
     */
    private function generate_sitemap() {
        $options = get_option($this->option_name);
        $post_limit = isset($options['post_limit']) ? intval($options['post_limit']) : 3000;
        $tag_limit = isset($options['tag_limit']) ? intval($options['tag_limit']) : 500;

        if ($cached = get_transient('sm_sitemap_cache')) return $cached;

        ob_start();
        ?>
<?php echo '<?xml version="1.0" encoding="UTF-8"?>'; ?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <!-- 首页 -->
    <url>
        <loc><?php echo esc_url(home_url('/')); ?></loc>
        <lastmod><?php echo $this->local_time(get_lastpostmodified('blog')); ?></lastmod>
        <changefreq>daily</changefreq>
        <priority>1.0</priority>
    </url>
    <?php
    // 文章
    $posts = get_posts([
        'post_type'      => 'post',
        'post_status'    => 'publish',
        'posts_per_page' => $post_limit,
        'orderby'        => 'modified',
        'order'          => 'DESC'
    ]);
    foreach ($posts as $p) {
        ?>
        <url>
            <loc><?php echo esc_url(get_permalink($p)); ?></loc>
            <lastmod><?php echo $this->local_time(get_post_modified_time('Y-m-d H:i:s', true, $p)); ?></lastmod>
            <changefreq>weekly</changefreq>
            <priority>0.8</priority>
        </url>
        <?php
    }
    // 页面
    $pages = get_pages(['sort_column' => 'post_modified', 'sort_order' => 'DESC']);
    foreach ($pages as $p) {
        ?>
        <url>
            <loc><?php echo esc_url(get_page_link($p->ID)); ?></loc>
            <lastmod><?php echo $this->local_time(get_post_modified_time('Y-m-d H:i:s', true, $p)); ?></lastmod>
            <changefreq>monthly</changefreq>
            <priority>0.6</priority>
        </url>
        <?php
    }
    // 标签
    $tags = get_terms([
        'taxonomy'   => 'post_tag',
        'hide_empty' => true,
        'orderby'    => 'count',
        'order'      => 'DESC',
        'number'     => $tag_limit
    ]);
    if (!empty($tags) && !is_wp_error($tags)) {
        foreach ($tags as $term) {
            ?>
            <url>
                <loc><?php echo esc_url(get_term_link($term)); ?></loc>
                <lastmod><?php echo $this->local_time(current_time('mysql')); ?></lastmod>
                <changefreq>weekly</changefreq>
                <priority>0.5</priority>
            </url>
            <?php
        }
    }
    // 其它分类法
    $taxonomies = get_taxonomies(['public' => true], 'objects');
    foreach ($taxonomies as $tax) {
        if ($tax->name === 'post_tag') continue;
        $terms = get_terms([
            'taxonomy'   => $tax->name,
            'hide_empty' => true,
            'orderby'    => 'count',
            'order'      => 'DESC',
            'number'     => 500
        ]);
        if (!empty($terms) && !is_wp_error($terms)) {
            foreach ($terms as $term) {
                ?>
                <url>
                    <loc><?php echo esc_url(get_term_link($term)); ?></loc>
                    <lastmod><?php echo $this->local_time(current_time('mysql')); ?></lastmod>
                    <changefreq>weekly</changefreq>
                    <priority>0.5</priority>
                </url>
                <?php
            }
        }
    }
    ?>
</urlset>
<?php
        $content = ob_get_clean();
        set_transient('sm_sitemap_cache', $content, 86400);
        return $content;
    }

    /**
     * 格式化本地时间，全部以WP后台设置时区为准
     */
    private function local_time($datetime) {
        $tz = wp_timezone();
        try {
            $dt = new DateTime($datetime, $tz);
        } catch (Exception $e) {
            $dt = new DateTime('now', $tz);
        }
        return $dt->format('Y-m-d\TH:i:sP');
    }

    public function add_admin_menu() {
        add_menu_page(
            '智能站点地图',
            '智能站点地图',
            'manage_options',
            'smart-sitemap',
            [$this, 'admin_interface'],
            'dashicons-location-alt',
            90
        );
    }

    public function admin_interface() {
        if (!current_user_can('manage_options')) return;
        $file_path = ABSPATH . $this->sitemap_file;
        $file_exists = file_exists($file_path);
        $file_url = esc_url(home_url('/' . $this->sitemap_file));
        $options = get_option($this->option_name);
        $post_limit = isset($options['post_limit']) ? intval($options['post_limit']) : 3000;
        $tag_limit = isset($options['tag_limit']) ? intval($options['tag_limit']) : 500;
        $hour = isset($options['cron_hour']) ? intval($options['cron_hour']) : 1;
        $tz = wp_timezone();
        ?>
        <div class="wrap aksu-sitemap-singlebox">
            <h1 class="aksu-title-main"><span class="dashicons dashicons-location-alt"></span> 智能站点地图</h1>

            <!-- 一键提交区块：页面顶部 -->
            <div class="aksu-card aksu-card-search" style="margin-bottom:26px;">
                <h2 class="aksu-h2-small"><span class="dashicons dashicons-share"></span> 一键提交到主流搜索引擎</h2>
                <div class="search-engine-buttons aksu-btn-group-small">
                    <a href="https://www.google.com/webmasters/tools/submit-url" class="button button-google aksu-btn-small" target="_blank"><span class="dashicons dashicons-google"></span> Google</a>
                    <a href="https://www.bing.com/webmaster/home" class="button button-bing aksu-btn-small" target="_blank"><span class="dashicons dashicons-search"></span> Bing</a>
                    <a href="https://ziyuan.baidu.com/linksubmit" class="button button-baidu aksu-btn-small" target="_blank"><span class="dashicons dashicons-admin-site"></span> 百度</a>
                </div>
            </div>

            <div class="aksu-status-row">
                <!-- 右侧：设置区块 -->
                <div class="aksu-status-cell aksu-setting-cell">
                    <h2 class="aksu-h2"><span class="dashicons dashicons-admin-generic"></span> 定时与数量设置</h2>
                    <form method="post" action="options.php">
                        <?php settings_fields('sm_sitemap_setting_group'); ?>
                        <table class="form-table">
                            <tr>
                                <th><span class="dashicons dashicons-clock"></span> 定时生成时间</th>
                                <td>
                                    <select name="<?php echo esc_attr($this->option_name); ?>[cron_hour]" style="width:90px;">
                                        <?php for ($i = 0; $i < 24; $i++) {
                                            printf('<option value="%d"%s>%02d:00</option>', $i, selected($hour, $i, false), $i);
                                        } ?>
                                    </select>
                                    <span class="description">每天的该小时自动生成sitemap（<?php echo esc_html($tz->getName()); ?>）</span>
                                    <?php
                                    $next = wp_next_scheduled('sm_daily_sitemap_update');
                                    if ($next) {
                                        $dt = new DateTime('@' . $next);
                                        $dt->setTimezone($tz);
                                        echo '<div style="margin-top:4px;color:#1976d2;">下次执行时间：' . esc_html($dt->format('Y-m-d H:i')) . '</div>';
                                    }
                                    ?>
                                </td>
                            </tr>
                            <tr>
                                <th><span class="dashicons dashicons-media-document"></span> 文章列表数量</th>
                                <td>
                                    <input type="number" name="<?php echo esc_attr($this->option_name); ?>[post_limit]" value="<?php echo esc_attr($post_limit); ?>" min="1" max="10000" style="width:100px;" />
                                    <span class="description">最大数量，默认3000</span>
                                </td>
                            </tr>
                            <tr>
                                <th><span class="dashicons dashicons-tag"></span> 标签列表数量</th>
                                <td>
                                    <input type="number" name="<?php echo esc_attr($this->option_name); ?>[tag_limit]" value="<?php echo esc_attr($tag_limit); ?>" min="1" max="2000" style="width:100px;" />
                                    <span class="description">最大数量，默认500</span>
                                </td>
                            </tr>
                        </table>
                        <?php submit_button('保存设置', 'primary', 'submit', false); ?>
                    </form>
                </div>
                <!-- 左侧：当前状态 -->
                <div class="aksu-status-cell aksu-status-submit">
                    <h2 class="aksu-h2"><span class="dashicons dashicons-info"></span> 当前状态</h2>
                    <ul class="aksu-status-list">
                        <li>
                            <span class="dashicons dashicons-calendar-alt"></span> 最后生成时间：
                            <strong>
                                <?php
                                if ($file_exists) {
                                    $timestamp = filemtime($file_path);
                                    $datetime = new DateTime('@' . $timestamp);
                                    $datetime->setTimezone($tz);
                                    echo esc_html($datetime->format('Y-m-d H:i'));
                                } else {
                                    echo '<span class="aksu-grey">尚未生成</span>';
                                }
                                ?>
                            </strong>
                        </li>
                        <li>
                            <span class="dashicons dashicons-archive"></span> 文件大小：
                            <strong><?php echo $file_exists ? esc_html(size_format(filesize($file_path))) : '0'; ?></strong>
                        </li>
                        <li>
                            <span class="dashicons dashicons-admin-links"></span> 访问地址：
                            <strong><a href="<?php echo $file_url; ?>" target="_blank"><?php echo $file_url; ?></a></strong>
                        </li>
                    </ul>
                    <div class="aksu-generate-btn" style="margin-top:18px;">
                        <form method="post" style="display:inline;">
                            <?php submit_button('立即生成站点地图', 'primary', 'generate_now', false, ['style' => 'font-size:1.1em;padding:8px 26px;']); ?>
                        </form>
                        <?php
                        if (isset($_POST['generate_now'])) {
                            if ($this->generate_sitemap_file()) {
                                echo '<div class="notice notice-success is-dismissible" style="margin-top:12px;"><p>✅ 站点地图已成功生成！</p></div>';
                            } else {
                                echo '<div class="notice notice-error is-dismissible" style="margin-top:12px;"><p>❌ 生成失败，请检查网站根目录写入权限</p></div>';
                            }
                        }
                        ?>
                    </div>
                </div>
            </div>
            <style>
            .aksu-sitemap-singlebox{max-width:980px;margin:auto;}
            .aksu-title-main{
                font-size:2.7em;
                font-weight:700;
                margin-bottom:28px;
                letter-spacing:2px;
                color:#1565c0;
                text-shadow:0 2px 8px #e5e5e5;
                display:flex;
                align-items:center;
                gap:8px;
            }
            .aksu-status-row{
                display:flex;
                gap:32px;
                flex-wrap:wrap;
                margin-top:0;
            }
            .aksu-status-cell{
                background:linear-gradient(135deg,#fafdff 0%,#e0edfa 100%);
                border-radius:12px;
                padding:32px 28px 18px 28px;
                box-shadow:0 2px 16px #e3eaf5;
                flex:1;
                min-width:340px;
                border:1.5px solid #e5ecfa;
            }
            .aksu-setting-cell{
                border-top:4px solid #1976d2;
            }
            .aksu-status-submit{
                border-top:4px solid #43a047;
            }
            .aksu-h2{
                font-size:1.26em;
                margin-top:0;
                margin-bottom:18px;
                font-weight:700;
                color:#1976d2;
                display:flex;
                align-items:center;
                gap:5px;
            }
            .aksu-h2-small{
                font-size:1em;
                margin-top:0;
                margin-bottom:12px;
                font-weight:600;
                color:#1565c0;
                display:flex;
                align-items:center;
                gap:5px;
            }
            .aksu-card{
                background:linear-gradient(90deg,#f5fafd 60%,#e9f0fa 100%);
                border-radius:10px;
                padding:13px 15px 10px 15px;
                box-shadow:0 2px 12px #e5eefa;
            }
            .aksu-card-search{
                border-left:5px solid #1976d2;
                max-width:420px;
            }
            .search-engine-buttons{margin-bottom:8px;}
            .aksu-btn-group-small{display:flex;gap:10px;}
            .aksu-btn-small{font-size:0.97em;padding:4px 18px 4px 16px;border-radius:18px;}
            .button-google{background:#4285f4;color:white;}
            .button-bing{background:#00809d;color:white;}
            .button-baidu{background:#2319dc;color:white;}
            .aksu-status-list{list-style:none;margin:0 0 0 0;padding:0 0 0 0;}
            .aksu-status-list li{
                padding:7px 0;
                font-size:1.03em;
                border-bottom:1px dashed #e3eaf5;
                display:flex;
                align-items:center;
                gap:6px;
            }
            .aksu-status-list li:last-child{border-bottom:none;}
            .aksu-generate-btn{margin-top:16px;}
            .form-table th{width:130px;font-weight:600;}
            .aksu-grey{color:#888;}
            .description{color:#b0b7c3;font-size:0.97em;}
            a{color:#1976d2;text-decoration:none;}
            a:hover{text-decoration:underline;}
            .notice-success{color:#43a047;background:#e9fbe8;border:1px solid #43a047;}
            .notice-error{color:#c62828;background:#fbe9e7;border:1px solid #c62828;}
            @media(max-width:1100px){
                .aksu-sitemap-singlebox{max-width:100%;padding:0 6px;}
                .aksu-status-row{flex-direction:column;}
                .aksu-card-search{max-width:100%;}
            }
            </style>
        </div>
        <?php
    }

    public function add_settings_link($links) {
        array_unshift($links, '<a href="' . admin_url('admin.php?page=smart-sitemap') . '">设置</a>');
        return $links;
    }
}

new Smart_Sitemap_Generator_V2();