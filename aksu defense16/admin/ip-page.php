<?php
if (!defined('ABSPATH')) exit;

// IP黑白名单管理
function aksu_ip_page() {
    if (isset($_POST['wpss_ip_save']) && check_admin_referer('wpss_ip')) {
        update_option('wpss_ip_whitelist', trim($_POST['wpss_ip_whitelist']));
        update_option('wpss_ip_blacklist', trim($_POST['wpss_ip_blacklist']));
        echo '<div class="updated"><p>IP黑白名单已保存。</p></div>';
    }
    $white = get_option('wpss_ip_whitelist', '');
    $black = get_option('wpss_ip_blacklist', '');
    ?>
    <div class="wrap">
        <h1>IP黑白名单</h1>
        <form method="post">
            <?php wp_nonce_field('wpss_ip'); ?>
            <table class="form-table">
                <tr>
                    <th>IP白名单</th>
                    <td>
                        <textarea name="wpss_ip_whitelist" rows="5" cols="60" placeholder="每行填写一个IP或通配符"><?php echo esc_textarea($white); ?></textarea>
                        <p class="description">支持如 192.168.1.1 或 192.168.*.*，支持IPV6。</p>
                    </td>
                </tr>
                <tr>
                    <th>IP黑名单</th>
                    <td>
                        <textarea name="wpss_ip_blacklist" rows="5" cols="60" placeholder="每行填写一个IP或通配符"><?php echo esc_textarea($black); ?></textarea>
                        <p class="description">支持如 1.2.3.4、10.10.*.*、2001:db8::1等。命中黑名单将直接拒绝访问。</p>
                    </td>
                </tr>
            </table>
            <p><button class="button button-primary" type="submit" name="wpss_ip_save">保存设置</button></p>
        </form>
    </div>
    <?php
}