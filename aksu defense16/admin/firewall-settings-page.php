<?php
if (!defined('ABSPATH')) exit;

// 防火墙配置页面
function aksu_firewall_settings_page() {
    // 保存操作
    if (isset($_POST['wpss_fw_save']) && check_admin_referer('wpss_fw_settings')) {
        update_option('wpss_fw_cc_status', isset($_POST['wpss_fw_cc_status']) ? 1 : 0);
        update_option('wpss_fw_cc_code', in_array($_POST['wpss_fw_cc_code'], ['403','400']) ? $_POST['wpss_fw_cc_code'] : '403');
        update_option('wpss_cc_limit', intval($_POST['wpss_cc_limit']));
        update_option('wpss_cc_period', isset($_POST['wpss_cc_period']) ? intval($_POST['wpss_cc_period']) : get_option('wpss_cc_period', 60));
        update_option('wpss_cc_blocktime', intval($_POST['wpss_cc_blocktime']));
        update_option('wpss_fw_injection_status', isset($_POST['wpss_fw_injection_status']) ? 1 : 0);
        update_option('wpss_fw_injection_code', in_array($_POST['wpss_fw_injection_code'], ['403','400']) ? $_POST['wpss_fw_injection_code'] : '403');
        update_option('wpss_fw_useragent_status', isset($_POST['wpss_fw_useragent_status']) ? 1 : 0);
        update_option('wpss_fw_useragent_code', in_array($_POST['wpss_fw_useragent_code'], ['403','400']) ? $_POST['wpss_fw_useragent_code'] : '403');
        update_option('wpss_fw_scan_status', isset($_POST['wpss_fw_scan_status']) ? 1 : 0);
        update_option('wpss_fw_scan_code', in_array($_POST['wpss_fw_scan_code'], ['403','400']) ? $_POST['wpss_fw_scan_code'] : '403');
        update_option('wpss_fw_cookie_status', isset($_POST['wpss_fw_cookie_status']) ? 1 : 0);
        update_option('wpss_fw_cookie_code', in_array($_POST['wpss_fw_cookie_code'], ['403','400']) ? $_POST['wpss_fw_cookie_code'] : '403');
        update_option('wpss_fw_upload_status', isset($_POST['wpss_fw_upload_status']) ? 1 : 0);
        update_option('wpss_fw_upload_code', in_array($_POST['wpss_fw_upload_code'], ['403','400']) ? $_POST['wpss_fw_upload_code'] : '403');
        update_option('wpss_fw_php_script_status', isset($_POST['wpss_fw_php_script_status']) ? 1 : 0);
        update_option('wpss_fw_php_script_code', in_array($_POST['wpss_fw_php_script_code'], ['403','400']) ? $_POST['wpss_fw_php_script_code'] : '403');
        update_option('wpss_fw_uri_status', isset($_POST['wpss_fw_uri_status']) ? 1 : 0);
        update_option('wpss_fw_uri_code', in_array($_POST['wpss_fw_uri_code'], ['403','400']) ? $_POST['wpss_fw_uri_code'] : '403');
        update_option('wpss_fw_uri_custom_status', isset($_POST['wpss_fw_uri_custom_status']) ? 1 : 0);
        update_option('wpss_fw_uri_custom_code', in_array($_POST['wpss_fw_uri_custom_code'], ['403','400']) ? $_POST['wpss_fw_uri_custom_code'] : '403');
        update_option('wpss_uri_custom_rules', sanitize_textarea_field($_POST['wpss_uri_custom_rules']));
        update_option('wpss_ua_blacklist', trim($_POST['wpss_ua_blacklist']));
        // 保存自定义HTTP响应体内容
        update_option('wpss_resp_html_400', wp_kses_post($_POST['wpss_resp_html_400']));
        update_option('wpss_resp_html_403', wp_kses_post($_POST['wpss_resp_html_403']));
        echo '<div class="updated"><p>设置已保存。</p></div>';
    }
    // 读取响应体内容
    $resp_html_400 = get_option('wpss_resp_html_400', '<h2>400 Bad Request</h2><p>您的请求有误或被拦截。</p>');
    $resp_html_403 = get_option('wpss_resp_html_403', '<h2>403 Forbidden</h2><p>您无权访问此页面。</p>');
    ?>
    <div class="wrap">
        <h1>防火墙规则设置</h1>
        <form method="post">
            <?php wp_nonce_field('wpss_fw_settings'); ?>
            <style>
                .wpss-fw-table th, .wpss-fw-table td {vertical-align: top;}
                .wpss-fw-table .fw-select-cell {padding-right: 6px; padding-left: 0;}
                .wpss-fw-table select { min-width: 70px;}
                .wpss-fw-textarea, .wpss-fw-example { width: 600px; max-width: 98%; }
                .wpss-fw-resp-textarea { width: 760px; max-width: 98%; min-height: 96px; }
            </style>
            <table class="form-table wpss-fw-table">
                <tr>
                    <th style="width:16%">防火墙规则</th>
                    <th style="width:10%">HTTP响应码</th>
                    <th>规则配置</th>
                </tr>
                <tr>
                    <th>CC攻击防御</th>
                    <td class="fw-select-cell">
                        <select name="wpss_fw_cc_code">
                            <option value="403" <?php selected(get_option('wpss_fw_cc_code', '403'), '403'); ?>>403</option>
                            <option value="400" <?php selected(get_option('wpss_fw_cc_code', '403'), '400'); ?>>400</option>
                        </select>
                    </td>
                    <td>
                        <label><input type="checkbox" name="wpss_fw_cc_status" value="1" <?php checked(get_option('wpss_fw_cc_status', 1)); ?>> 启用</label>
                        <br>单位时间<code>秒</code>内最多 <input type="number" name="wpss_cc_limit" value="<?php echo esc_attr(get_option('wpss_cc_limit', 60)); ?>" style="width:70px;"> 次请求，
                        周期 <input type="number" name="wpss_cc_period" value="<?php echo esc_attr(get_option('wpss_cc_period', 60)); ?>" style="width:70px;"> 秒，
                        封锁 <input type="number" name="wpss_cc_blocktime" value="<?php echo esc_attr(get_option('wpss_cc_blocktime', 1800)); ?>" style="width:70px;"> 秒
                    </td>
                </tr>
                <tr>
                    <th>SQL/XSS注入拦截</th>
                    <td class="fw-select-cell">
                        <select name="wpss_fw_injection_code">
                            <option value="403" <?php selected(get_option('wpss_fw_injection_code', '403'), '403'); ?>>403</option>
                            <option value="400" <?php selected(get_option('wpss_fw_injection_code', '403'), '400'); ?>>400</option>
                        </select>
                    </td>
                    <td>
                        <label><input type="checkbox" name="wpss_fw_injection_status" value="1" <?php checked(get_option('wpss_fw_injection_status', 1)); ?>> 启用</label>
                    </td>
                </tr>
                <tr>
                    <th>恶意User-Agent拦截</th>
                    <td class="fw-select-cell">
                        <select name="wpss_fw_useragent_code">
                            <option value="403" <?php selected(get_option('wpss_fw_useragent_code', '403'), '403'); ?>>403</option>
                            <option value="400" <?php selected(get_option('wpss_fw_useragent_code', '403'), '400'); ?>>400</option>
                        </select>
                    </td>
                    <td>
                        <label><input type="checkbox" name="wpss_fw_useragent_status" value="1" <?php checked(get_option('wpss_fw_useragent_status', 1)); ?>> 启用</label>
                        <br>
                        <label><b>自定义User-Agent黑名单：</b></label><br>
                        <textarea name="wpss_ua_blacklist" rows="3" class="wpss-fw-textarea" placeholder="*curl*|*IE*|*chrome*|*firefox*"><?php echo esc_textarea(get_option('wpss_ua_blacklist', '')); ?></textarea>
                        <p class="description" style="color:#888;">
                            <b>填写说明：</b>每行填写一组规则，同一行内可用 <b>|</b> 分隔多个内容，命中任意一个即拦截。
                            <span style="cursor:pointer;color:#2271b1;" onclick="var ex=document.getElementById('ua_blacklist_example');ex.style.display=ex.style.display=='none'?'block':'none';this.style.fontWeight=this.style.fontWeight=='bold'?'':'bold';">[示例]</span>
                            <span id="ua_blacklist_example" class="wpss-fw-example" style="display:none;padding:8px 12px;background:#f6f6f6;border-radius:4px;border:1px solid #eee; color:#444;">
                                <br>- <b>*</b> 代表任意字符串。例如：<code>*crawler*</code> 匹配包含 crawler 的所有UA。<br>
                                - <code>abc*</code> 匹配以 abc 开头的UA。<br>
                                - <code>*abc</code> 匹配以 abc 结尾的UA。<br>
                                - <code>abc</code> 匹配等于 abc 的UA。<br>
                                - <code>*curl*</code> （可拦截包含curl的UA）<br>
                                <code>chrome|firefox</code> （可拦截包含chrome或firefox的UA）<br>
                                <code>BadBot*</code> （可拦截以BadBot开头的UA）<br>
                                - 多个规则用 <code>|</code> 隔开，不要换行。
                            </span>
                        </p>
                    </td>
                </tr>
                <tr>
                    <th>敏感路径扫描拦截</th>
                    <td class="fw-select-cell">
                        <select name="wpss_fw_scan_code">
                            <option value="403" <?php selected(get_option('wpss_fw_scan_code', '403'), '403'); ?>>403</option>
                            <option value="400" <?php selected(get_option('wpss_fw_scan_code', '403'), '400'); ?>>400</option>
                        </select>
                    </td>
                    <td>
                        <label><input type="checkbox" name="wpss_fw_scan_status" value="1" <?php checked(get_option('wpss_fw_scan_status', 1)); ?>> 启用</label>
                    </td>
                </tr>
                <tr>
                    <th>Cookie注入拦截</th>
                    <td class="fw-select-cell">
                        <select name="wpss_fw_cookie_code">
                            <option value="403" <?php selected(get_option('wpss_fw_cookie_code', '403'), '403'); ?>>403</option>
                            <option value="400" <?php selected(get_option('wpss_fw_cookie_code', '403'), '400'); ?>>400</option>
                        </select>
                    </td>
                    <td>
                        <label><input type="checkbox" name="wpss_fw_cookie_status" value="1" <?php checked(get_option('wpss_fw_cookie_status', 1)); ?>> 启用</label>
                    </td>
                </tr>
                <tr>
                    <th>文件上传拦截</th>
                    <td class="fw-select-cell">
                        <select name="wpss_fw_upload_code">
                            <option value="403" <?php selected(get_option('wpss_fw_upload_code', '403'), '403'); ?>>403</option>
                            <option value="400" <?php selected(get_option('wpss_fw_upload_code', '403'), '400'); ?>>400</option>
                        </select><br>
                        <select name="wpss_fw_php_script_code">
                            <option value="403" <?php selected(get_option('wpss_fw_php_script_code', '403'), '403'); ?>>403</option>
                            <option value="400" <?php selected(get_option('wpss_fw_php_script_code', '403'), '400'); ?>>400</option>
                        </select>
                    </td>
                    <td>
                        <label><input type="checkbox" name="wpss_fw_upload_status" value="1" <?php checked(get_option('wpss_fw_upload_status', 1)); ?>> 启用</label>
                        &nbsp;|&nbsp;
                        <label><input type="checkbox" name="wpss_fw_php_script_status" value="1" <?php checked(get_option('wpss_fw_php_script_status', 1)); ?>> 阻止上传PHP脚本</label>
                    </td>
                </tr>
                <tr>
                    <th>URI规则拦截</th>
                    <td class="fw-select-cell">
                        <select name="wpss_fw_uri_code">
                            <option value="403" <?php selected(get_option('wpss_fw_uri_code', '403'), '403'); ?>>403</option>
                            <option value="400" <?php selected(get_option('wpss_fw_uri_code', '403'), '400'); ?>>400</option>
                        </select><br>
                        <select name="wpss_fw_uri_custom_code">
                            <option value="403" <?php selected(get_option('wpss_fw_uri_custom_code', '403'), '403'); ?>>403</option>
                            <option value="400" <?php selected(get_option('wpss_fw_uri_custom_code', '403'), '400'); ?>>400</option>
                        </select>
                    </td>
                    <td>
                        <label><input type="checkbox" name="wpss_fw_uri_status" value="1" <?php checked(get_option('wpss_fw_uri_status', 1)); ?>> 启用路径穿越/敏感字符拦截</label>
                        <br>
                        <label><input type="checkbox" name="wpss_fw_uri_custom_status" value="1" <?php checked(get_option('wpss_fw_uri_custom_status', 0)); ?>> 启用自定义URI规则</label>
                        <br>
                        <textarea name="wpss_uri_custom_rules" rows="3" class="wpss-fw-textarea" placeholder="/example-uri"><?php echo esc_textarea(get_option('wpss_uri_custom_rules', '')); ?></textarea>
                        <p class="description" style="color:#888;">
                            <b>填写说明：</b>每行填写一组规则，同一行内可用 <b>|</b> 分隔多个内容，命中任意一个即拦截。
                            <span style="cursor:pointer;color:#2271b1;" onclick="var ex=document.getElementById('uri_rules_example');ex.style.display=ex.style.display=='none'?'block':'none';this.style.fontWeight=this.style.fontWeight=='bold'?'':'bold';">[示例]</span>
                            <span id="uri_rules_example" class="wpss-fw-example" style="display:none;padding:8px 12px;background:#f6f6f6;border-radius:4px;border:1px solid #eee; color:#444;">
                                <br><code>/admin|/manage</code> （命中 /admin 或 /manage 即拦截）<br>
                                <code>.php|.asp</code> （命中 .php 或 .asp 即拦截）<br>
                                <code>/api/v1/</code> （命中 /api/v1/ 即拦截）<br>
                                <code>/^\\/debug\\//</code> （正则，命中以 /debug/ 开头路径即拦截）<br>
                                <b>注意：</b>正则表达式需以 <code>/</code> 开头和结尾，其余为普通关键词匹配。
                            </span>
                        </p>
                    </td>
                </tr>
                <tr>
                    <th style="width:16%;">400错误代码</th>
                    <td colspan="2">
                        <textarea name="wpss_resp_html_400" class="wpss-fw-resp-textarea" rows="4"><?php echo esc_textarea($resp_html_400); ?></textarea>
                        <div style="color:#888;font-size:13px;">
                            此处填写反馈给客户端的400错误页面内容，支持HTML。<br>
                            <strong>温馨提示：</strong>如需在页面中动态显示拦截项目名称，请在内容中插入 <code>{scene}</code> 或 <code>{防护项目}</code> 占位符。
                        </div>
                    </td>
                </tr>
                <tr>
                    <th style="width:16%;">403错误代码</th>
                    <td colspan="2">
                        <textarea name="wpss_resp_html_403" class="wpss-fw-resp-textarea" rows="4"><?php echo esc_textarea($resp_html_403); ?></textarea>
                        <div style="color:#888;font-size:13px;">
                            此处填写反馈给客户端的403错误页面内容，支持HTML。<br>
                            <strong>温馨提示：</strong>如需在页面中动态显示拦截项目名称，请在内容中插入 <code>{scene}</code> 或 <code>{防护项目}</code> 占位符。
                        </div>
                    </td>
                </tr>
            </table>
            <p><button class="button button-primary" type="submit" name="wpss_fw_save">保存设置</button></p>
        </form>
    </div>
<?php }