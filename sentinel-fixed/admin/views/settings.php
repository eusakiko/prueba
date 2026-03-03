<?php
/**
 * Settings view.
 *
 * @package WP_Sentinel_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

require SENTINEL_PLUGIN_DIR . 'admin/views/partials/header.php';

$settings = get_option( 'sentinel_settings', array() );
$defaults = array(
	'scan_frequency'       => 'daily',
	'scheduled_scan_type'  => 'quick',
	'backup_before_action' => true,
	'alert_email'          => get_option( 'admin_email' ),
	'alert_channels'       => array( 'email' ),
	'log_retention_days'   => 90,
	'async_scanning'       => true,
	'wpscan_api_key'       => '',
	'slack_webhook'        => '',
	'telegram_bot_token'   => '',
	'telegram_chat_id'     => '',
	'company_name'         => get_option( 'blogname' ),
	'company_logo'         => '',
	'2fa_enabled'          => false,
	'2fa_required_roles'   => array(),
	'login_max_attempts'   => 5,
	'login_lockout_mins'   => 15,
);
$settings = wp_parse_args( $settings, $defaults );

// ── Scheduled scan info ────────────────────────────────────────────────────
$next_scan     = wp_next_scheduled( 'sentinel_scheduled_scan' );
$last_scan_row = Sentinel_DB::get_latest_scan();
$last_scan_ts  = $last_scan_row ? strtotime( $last_scan_row->completed_at ) : false;

// ── Available roles for 2FA enforcement ───────────────────────────────────
$all_roles    = wp_roles()->roles;
$role_choices = array_map(
	static function ( $role ) {
		return translate_user_role( $role['name'] );
	},
	$all_roles
);
?>

<div class="wrap sentinel-wrap">

	<div class="sentinel-page-header">
		<div class="sentinel-header-left">
			<span class="dashicons dashicons-admin-settings sentinel-header-icon"></span>
			<h1><?php esc_html_e( 'Settings', 'wp-sentinel-security' ); ?></h1>
		</div>
	</div>

	<form method="post" action="options.php">
		<?php settings_fields( 'sentinel_settings_group' ); ?>

		<!-- General Settings -->
		<div class="sentinel-card">
			<h2><?php esc_html_e( 'General Settings', 'wp-sentinel-security' ); ?></h2>
			<table class="form-table">
				<tr>
					<th scope="row">
						<label for="sentinel_backup_before_action"><?php esc_html_e( 'Backup Before Action', 'wp-sentinel-security' ); ?></label>
					</th>
					<td>
						<input type="checkbox" name="sentinel_settings[backup_before_action]" id="sentinel_backup_before_action" value="1" <?php checked( $settings['backup_before_action'] ); ?> />
						<label for="sentinel_backup_before_action"><?php esc_html_e( 'Create a backup before applying any security fix', 'wp-sentinel-security' ); ?></label>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="sentinel_log_retention"><?php esc_html_e( 'Log Retention (days)', 'wp-sentinel-security' ); ?></label>
					</th>
					<td>
						<input type="number" name="sentinel_settings[log_retention_days]" id="sentinel_log_retention" value="<?php echo esc_attr( $settings['log_retention_days'] ); ?>" min="1" max="365" class="small-text" />
					</td>
				</tr>
				<tr>
					<th scope="row">
						<?php esc_html_e( 'Brute-Force Protection', 'wp-sentinel-security' ); ?>
					</th>
					<td>
						<div style="display:flex;flex-wrap:wrap;gap:20px;align-items:center;">
							<label style="display:flex;align-items:center;gap:8px;">
								<?php esc_html_e( 'Max attempts:', 'wp-sentinel-security' ); ?>
								<input type="number"
									name="sentinel_settings[login_max_attempts]"
									id="sentinel_login_max_attempts"
									value="<?php echo esc_attr( $settings['login_max_attempts'] ?? 5 ); ?>"
									min="1" max="100" class="small-text" style="width:60px;" />
							</label>
							<label style="display:flex;align-items:center;gap:8px;">
								<?php esc_html_e( 'Lockout duration (min):', 'wp-sentinel-security' ); ?>
								<input type="number"
									name="sentinel_settings[login_lockout_mins]"
									id="sentinel_login_lockout_mins"
									value="<?php echo esc_attr( $settings['login_lockout_mins'] ?? 15 ); ?>"
									min="1" max="1440" class="small-text" style="width:70px;" />
							</label>
						</div>
						<p class="description">
							<?php esc_html_e( 'Applies when "Limit Login Attempts" is enabled in Hardening. Current lockouts are stored as transients and cleared automatically when they expire.', 'wp-sentinel-security' ); ?>
						</p>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="sentinel_async_scanning"><?php esc_html_e( 'Async Scanning', 'wp-sentinel-security' ); ?></label>
					</th>
					<td>
						<input type="checkbox" name="sentinel_settings[async_scanning]" id="sentinel_async_scanning" value="1" <?php checked( $settings['async_scanning'] ); ?> />
						<label for="sentinel_async_scanning"><?php esc_html_e( 'Run scans asynchronously (recommended)', 'wp-sentinel-security' ); ?></label>
					</td>
				</tr>
			</table>
		</div>

		<!-- API Keys -->
		<div class="sentinel-card">
			<h2><?php esc_html_e( 'API Keys', 'wp-sentinel-security' ); ?></h2>
			<table class="form-table">
				<tr>
					<th scope="row">
						<label for="sentinel_wpscan_api_key"><?php esc_html_e( 'WPScan API Key', 'wp-sentinel-security' ); ?></label>
					</th>
					<td>
						<input type="password" name="sentinel_settings[wpscan_api_key]" id="sentinel_wpscan_api_key" value="<?php echo esc_attr( $settings['wpscan_api_key'] ); ?>" class="regular-text" autocomplete="off" />
						<p class="description">
							<?php
							printf(
								/* translators: %s: WPScan website URL */
								esc_html__( 'Get a free API key from %s', 'wp-sentinel-security' ),
								'<a href="https://wpscan.com/" target="_blank" rel="noopener noreferrer">wpscan.com</a>'
							);
							?>
						</p>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="sentinel_gsb_key"><?php esc_html_e( 'Google Safe Browsing API Key', 'wp-sentinel-security' ); ?></label>
					</th>
					<td>
						<input type="password" name="sentinel_settings[google_safe_browsing_key]" id="sentinel_gsb_key" value="<?php echo esc_attr( $settings['google_safe_browsing_key'] ?? '' ); ?>" class="regular-text" autocomplete="off" />
						<p class="description">
							<?php
							printf(
								esc_html__( 'Required for Google Safe Browsing blacklist checks in the Intelligence Layer. Get a free key from the %s.', 'wp-sentinel-security' ),
								'<a href="https://developers.google.com/safe-browsing/v4/get-started" target="_blank" rel="noopener noreferrer">Google Cloud Console</a>'
							);
							?>
						</p>
					</td>
				</tr>
			</table>
		</div>

		<!-- Alert Settings -->
		<div class="sentinel-card">
			<h2><?php esc_html_e( 'Alert Settings', 'wp-sentinel-security' ); ?></h2>
			<table class="form-table">
				<tr>
					<th scope="row">
						<label for="sentinel_alert_email"><?php esc_html_e( 'Alert Email', 'wp-sentinel-security' ); ?></label>
					</th>
					<td>
						<input type="email" name="sentinel_settings[alert_email]" id="sentinel_alert_email" value="<?php echo esc_attr( $settings['alert_email'] ); ?>" class="regular-text" />
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Alert Channels', 'wp-sentinel-security' ); ?></th>
					<td>
						<label>
							<input type="checkbox" name="sentinel_settings[alert_channels][]" value="email" <?php checked( in_array( 'email', (array) $settings['alert_channels'], true ) ); ?> />
							<?php esc_html_e( 'Email', 'wp-sentinel-security' ); ?>
						</label><br />
						<label>
							<input type="checkbox" name="sentinel_settings[alert_channels][]" value="slack" <?php checked( in_array( 'slack', (array) $settings['alert_channels'], true ) ); ?> />
							<?php esc_html_e( 'Slack', 'wp-sentinel-security' ); ?>
						</label><br />
						<label>
							<input type="checkbox" name="sentinel_settings[alert_channels][]" value="telegram" <?php checked( in_array( 'telegram', (array) $settings['alert_channels'], true ) ); ?> />
							<?php esc_html_e( 'Telegram', 'wp-sentinel-security' ); ?>
						</label>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="sentinel_slack_webhook"><?php esc_html_e( 'Slack Webhook URL', 'wp-sentinel-security' ); ?></label>
					</th>
					<td>
						<input type="url" name="sentinel_settings[slack_webhook]" id="sentinel_slack_webhook" value="<?php echo esc_attr( $settings['slack_webhook'] ); ?>" class="regular-text" />
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="sentinel_telegram_bot_token"><?php esc_html_e( 'Telegram Bot Token', 'wp-sentinel-security' ); ?></label>
					</th>
					<td>
						<input type="password" name="sentinel_settings[telegram_bot_token]" id="sentinel_telegram_bot_token" value="<?php echo esc_attr( $settings['telegram_bot_token'] ); ?>" class="regular-text" autocomplete="off" />
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="sentinel_telegram_chat_id"><?php esc_html_e( 'Telegram Chat ID', 'wp-sentinel-security' ); ?></label>
					</th>
					<td>
						<input type="text" name="sentinel_settings[telegram_chat_id]" id="sentinel_telegram_chat_id" value="<?php echo esc_attr( $settings['telegram_chat_id'] ); ?>" class="regular-text" />
					</td>
				</tr>
			</table>
		</div>

		<!-- Branding -->
		<div class="sentinel-card">
			<h2><?php esc_html_e( 'Branding', 'wp-sentinel-security' ); ?></h2>
			<table class="form-table">
				<tr>
					<th scope="row">
						<label for="sentinel_company_name"><?php esc_html_e( 'Company Name', 'wp-sentinel-security' ); ?></label>
					</th>
					<td>
						<input type="text" name="sentinel_settings[company_name]" id="sentinel_company_name" value="<?php echo esc_attr( $settings['company_name'] ); ?>" class="regular-text" />
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="sentinel_company_logo"><?php esc_html_e( 'Company Logo URL', 'wp-sentinel-security' ); ?></label>
					</th>
					<td>
						<input type="url" name="sentinel_settings[company_logo]" id="sentinel_company_logo" value="<?php echo esc_attr( $settings['company_logo'] ); ?>" class="regular-text" />
					</td>
				</tr>
			</table>
		</div>

		<!-- Malware Scanner Whitelist -->
		<div class="sentinel-card">
			<h2><?php esc_html_e( 'Malware Scanner', 'wp-sentinel-security' ); ?></h2>
			<p style="color:#64748b;font-size:13px;margin-bottom:16px;">
				<?php esc_html_e( 'Paths listed here are skipped during malware scans. One path per line, relative to the WordPress root (e.g. wp-content/plugins/my-plugin/lib/).', 'wp-sentinel-security' ); ?>
			</p>
			<table class="form-table">
				<tr>
					<th scope="row">
						<label for="sentinel_malware_whitelist"><?php esc_html_e( 'Scan Whitelist', 'wp-sentinel-security' ); ?></label>
					</th>
					<td>
						<?php
						$wl_paths = $settings['malware_scan_whitelist'] ?? array();
						if ( ! is_array( $wl_paths ) ) { $wl_paths = array(); }
						?>
						<textarea
							name="sentinel_settings[malware_scan_whitelist_raw]"
							id="sentinel_malware_whitelist"
							rows="6"
							class="large-text code"
							placeholder="wp-content/plugins/my-plugin/some-file.php"
						><?php echo esc_textarea( implode( "\n", $wl_paths ) ); ?></textarea>
						<p class="description">
							<?php esc_html_e( 'The plugin\'s own directory is always excluded automatically.', 'wp-sentinel-security' ); ?>
						</p>
					</td>
				</tr>
			</table>
		</div>

		<!-- Scheduled Scans -->
		<div class="sentinel-card">
			<h2><?php esc_html_e( 'Scheduled Scans', 'wp-sentinel-security' ); ?></h2>

			<!-- Last / next scan status row -->
			<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:20px;padding:16px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;">
				<div>
					<p style="margin:0 0 4px;font-size:11px;text-transform:uppercase;color:#888;font-weight:600;">
						<?php esc_html_e( 'Last Scheduled Scan', 'wp-sentinel-security' ); ?>
					</p>
					<p style="margin:0;font-size:14px;font-weight:500;">
						<?php
						if ( $last_scan_ts ) {
							echo esc_html( human_time_diff( $last_scan_ts, time() ) . ' ' . __( 'ago', 'wp-sentinel-security' ) );
							echo ' <span style="color:#888;font-weight:400;">(' . esc_html( date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $last_scan_ts ) ) . ')</span>';
						} else {
							echo '<span style="color:#888;">' . esc_html__( 'No scan recorded yet', 'wp-sentinel-security' ) . '</span>';
						}
						?>
					</p>
				</div>
				<div>
					<p style="margin:0 0 4px;font-size:11px;text-transform:uppercase;color:#888;font-weight:600;">
						<?php esc_html_e( 'Next Scheduled Scan', 'wp-sentinel-security' ); ?>
					</p>
					<p style="margin:0;font-size:14px;font-weight:500;">
						<?php
						if ( $next_scan ) {
							echo esc_html( __( 'In ', 'wp-sentinel-security' ) . human_time_diff( time(), $next_scan ) );
							echo ' <span style="color:#888;font-weight:400;">(' . esc_html( date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $next_scan ) ) . ')</span>';
						} else {
							echo '<span style="color:#c62828;">' . esc_html__( 'Not scheduled — save settings to reschedule', 'wp-sentinel-security' ) . '</span>';
						}
						?>
					</p>
				</div>
			</div>

			<table class="form-table">
				<tr>
					<th scope="row">
						<label for="sentinel_scan_frequency"><?php esc_html_e( 'Scan Frequency', 'wp-sentinel-security' ); ?></label>
					</th>
					<td>
						<select name="sentinel_settings[scan_frequency]" id="sentinel_scan_frequency">
							<option value="hourly"     <?php selected( $settings['scan_frequency'], 'hourly' ); ?>><?php esc_html_e( 'Hourly', 'wp-sentinel-security' ); ?></option>
							<option value="twicedaily" <?php selected( $settings['scan_frequency'], 'twicedaily' ); ?>><?php esc_html_e( 'Twice Daily', 'wp-sentinel-security' ); ?></option>
							<option value="daily"      <?php selected( $settings['scan_frequency'], 'daily' ); ?>><?php esc_html_e( 'Daily', 'wp-sentinel-security' ); ?></option>
							<option value="weekly"     <?php selected( $settings['scan_frequency'], 'weekly' ); ?>><?php esc_html_e( 'Weekly', 'wp-sentinel-security' ); ?></option>
						</select>
						<p class="description"><?php esc_html_e( 'Changing this value reschedules the cron event automatically on save.', 'wp-sentinel-security' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="sentinel_scheduled_scan_type"><?php esc_html_e( 'Scheduled Scan Type', 'wp-sentinel-security' ); ?></label>
					</th>
					<td>
						<select name="sentinel_settings[scheduled_scan_type]" id="sentinel_scheduled_scan_type">
							<option value="quick" <?php selected( $settings['scheduled_scan_type'], 'quick' ); ?>>
								<?php esc_html_e( 'Quick — core, plugins, config (1–2 min)', 'wp-sentinel-security' ); ?>
							</option>
							<option value="full" <?php selected( $settings['scheduled_scan_type'], 'full' ); ?>>
								<?php esc_html_e( 'Full — all modules (5–10 min)', 'wp-sentinel-security' ); ?>
							</option>
						</select>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Run Immediately', 'wp-sentinel-security' ); ?></th>
					<td>
						<button type="button" id="sentinel-run-now-btn" class="button button-secondary">
							<?php esc_html_e( 'Run scheduled scan now', 'wp-sentinel-security' ); ?>
						</button>
						<span id="sentinel-run-now-status" style="margin-left:10px;font-size:13px;"></span>
						<p class="description">
							<?php esc_html_e( 'Triggers the next cron event immediately without waiting for the scheduled time.', 'wp-sentinel-security' ); ?>
						</p>
					</td>
				</tr>
			</table>
		</div>

		<!-- Two-Factor Authentication -->
		<div class="sentinel-card">
			<h2><?php esc_html_e( 'Two-Factor Authentication', 'wp-sentinel-security' ); ?></h2>
			<p style="color:#64748b;font-size:13px;margin-bottom:8px;">
				<?php esc_html_e( 'When enabled, users can configure TOTP-based 2FA on their Profile page. Roles listed as required must set up 2FA before they can use the dashboard.', 'wp-sentinel-security' ); ?>
			</p>
			<table class="form-table">
				<tr>
					<th scope="row">
						<label for="sentinel_2fa_enabled"><?php esc_html_e( 'Enable 2FA Feature', 'wp-sentinel-security' ); ?></label>
					</th>
					<td>
						<input type="checkbox"
							name="sentinel_settings[2fa_enabled]"
							id="sentinel_2fa_enabled"
							value="1"
							<?php checked( $settings['2fa_enabled'] ); ?>>
						<label for="sentinel_2fa_enabled">
							<?php esc_html_e( 'Allow users to configure two-factor authentication', 'wp-sentinel-security' ); ?>
						</label>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Require 2FA for Roles', 'wp-sentinel-security' ); ?></th>
					<td>
						<?php foreach ( $role_choices as $role_slug => $role_label ) : ?>
							<label style="display:block;margin-bottom:4px;">
								<input
									type="checkbox"
									name="sentinel_settings[2fa_required_roles][]"
									value="<?php echo esc_attr( $role_slug ); ?>"
									<?php checked( in_array( $role_slug, (array) $settings['2fa_required_roles'], true ) ); ?>>
								<?php echo esc_html( $role_label ); ?>
							</label>
						<?php endforeach; ?>
						<p class="description">
							<?php esc_html_e( 'Users in checked roles who have not set up 2FA will be redirected to their profile on login.', 'wp-sentinel-security' ); ?>
						</p>
					</td>
				</tr>
			</table>
		</div>

		<!-- Rate Limiting -->
		<div class="sentinel-card">
			<h2><?php esc_html_e( 'Rate Limiting', 'wp-sentinel-security' ); ?></h2>
			<p style="margin-top:0;color:#64748b;font-size:13px;">
				<?php esc_html_e( 'Automatically block IPs that send too many requests in a short window. Requires the WAF to be enabled.', 'wp-sentinel-security' ); ?>
			</p>
			<table class="form-table">
				<tr>
					<th scope="row"><?php esc_html_e( 'Enable Rate Limiting', 'wp-sentinel-security' ); ?></th>
					<td>
						<label>
							<input type="checkbox" name="sentinel_settings[rate_limit_enabled]" value="1"
								<?php checked( ! empty( $settings['rate_limit_enabled'] ) ); ?> />
							<?php esc_html_e( 'Throttle excessive requests per IP', 'wp-sentinel-security' ); ?>
						</label>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Requests / Window', 'wp-sentinel-security' ); ?></th>
					<td style="display:flex;flex-wrap:wrap;gap:20px;align-items:center;">
						<label style="display:flex;align-items:center;gap:8px;">
							<?php esc_html_e( 'Max requests:', 'wp-sentinel-security' ); ?>
							<input type="number" name="sentinel_settings[rate_limit_requests]"
								value="<?php echo esc_attr( $settings['rate_limit_requests'] ?? 120 ); ?>"
								min="1" max="10000" class="small-text" style="width:70px;" />
						</label>
						<label style="display:flex;align-items:center;gap:8px;">
							<?php esc_html_e( 'Window (seconds):', 'wp-sentinel-security' ); ?>
							<input type="number" name="sentinel_settings[rate_limit_window]"
								value="<?php echo esc_attr( $settings['rate_limit_window'] ?? 60 ); ?>"
								min="1" max="3600" class="small-text" style="width:70px;" />
						</label>
						<p class="description" style="width:100%;margin:4px 0 0;">
							<?php esc_html_e( 'Default: 120 requests per 60-second window. Returning a 429 response to IPs over this threshold.', 'wp-sentinel-security' ); ?>
						</p>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="sentinel_rl_whitelist"><?php esc_html_e( 'Whitelist Paths', 'wp-sentinel-security' ); ?></label>
					</th>
					<td>
						<textarea name="sentinel_settings[rate_limit_whitelist_raw]" id="sentinel_rl_whitelist"
							rows="4" class="large-text code"
							placeholder="/wp-cron.php&#10;/wp-json/my-plugin/"
						><?php echo esc_textarea( implode( "\n", (array) ( $settings['rate_limit_whitelist'] ?? array() ) ) ); ?></textarea>
						<p class="description">
							<?php esc_html_e( 'One path prefix per line. Requests matching these paths are never rate-limited (useful for cron, REST, payment callbacks).', 'wp-sentinel-security' ); ?>
						</p>
					</td>
				</tr>
			</table>
		</div>

		<!-- ══════════════════════════════════════════════════════════
		     Trusted Proxy IPs
		     ══════════════════════════════════════════════════════════ -->
		<div class="sentinel-card">
			<h2><?php esc_html_e( 'Trusted Proxy IPs', 'wp-sentinel-security' ); ?></h2>
			<p class="description" style="margin-bottom:16px;">
				<?php esc_html_e( 'Enter the IPs or CIDR ranges of your reverse proxies (Cloudflare, AWS ALB, Nginx, etc.). Only connections that arrive directly from these IPs will be trusted for rate-limiting and WAF purposes. Leave empty to rely on REMOTE_ADDR only.', 'wp-sentinel-security' ); ?>
			</p>

			<?php
			// Pre-populate well-known Cloudflare IPv4 ranges as a convenience.
			$cf_ipv4 = array(
				'103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
				'104.16.0.0/13',   '104.24.0.0/14',   '108.162.192.0/18',
				'131.0.72.0/22',   '141.101.64.0/18',  '162.158.0.0/15',
				'172.64.0.0/13',   '173.245.48.0/20',  '188.114.96.0/20',
				'190.93.240.0/20', '197.234.240.0/22', '198.41.128.0/17',
			);
			$cf_ipv6 = array(
				'2400:cb00::/32', '2606:4700::/32', '2803:f800::/32',
				'2405:b500::/32', '2405:8100::/32', '2a06:98c0::/29',
				'2c0f:f248::/32',
			);
			$trusted_raw = (array) ( $settings['trusted_proxy_ips_raw'] ?? array() );
			?>

			<table class="form-table">
				<tr>
					<th scope="row">
						<label for="sentinel_trusted_proxies"><?php esc_html_e( 'Trusted Proxy IPs / CIDRs', 'wp-sentinel-security' ); ?></label>
					</th>
					<td>
						<textarea name="sentinel_settings[trusted_proxy_ips_raw]" id="sentinel_trusted_proxies"
							rows="6" class="large-text code"
							placeholder="203.0.113.1&#10;198.51.100.0/24"
						><?php echo esc_textarea( implode( "\n", $trusted_raw ) ); ?></textarea>
						<p class="description">
							<?php esc_html_e( 'One IP or CIDR per line.', 'wp-sentinel-security' ); ?>
						</p>
						<div style="margin-top:10px;display:flex;gap:10px;flex-wrap:wrap;">
							<button type="button" id="btn-preset-cloudflare" class="button">
								&#9729; <?php esc_html_e( 'Import Cloudflare IPs', 'wp-sentinel-security' ); ?>
							</button>
							<button type="button" id="btn-clear-proxies" class="button">
								&#x2715; <?php esc_html_e( 'Clear', 'wp-sentinel-security' ); ?>
							</button>
						</div>
						<script>
						(function($){
							var cf = <?php echo wp_json_encode( array_merge( $cf_ipv4, $cf_ipv6 ) ); ?>;
							$('#btn-preset-cloudflare').on('click', function(){
								var $ta = $('#sentinel_trusted_proxies');
								var existing = $ta.val().split('\n').map($.trim).filter(Boolean);
								var merged   = $.unique( existing.concat(cf) );
								$ta.val( merged.join('\n') );
							});
							$('#btn-clear-proxies').on('click', function(){
								$('#sentinel_trusted_proxies').val('');
							});
						}(jQuery));
						</script>
					</td>
				</tr>
			</table>
		</div>

		<!-- ══════════════════════════════════════════════════════════
		     WAF Custom Rules
		     ══════════════════════════════════════════════════════════ -->
		<div class="sentinel-card" id="sentinel-waf-custom-rules-card">
			<h2><?php esc_html_e( 'WAF Custom Rules', 'wp-sentinel-security' ); ?></h2>
			<p class="description" style="margin-bottom:16px;">
				<?php esc_html_e( 'Add your own WAF detection rules as PHP-compatible regular expressions. Rules are tested against URL, query string, POST body, cookies, and User-Agent. Use the Test button to validate the regex before saving.', 'wp-sentinel-security' ); ?>
			</p>

			<?php $custom_rules = (array) ( $settings['waf_custom_rules'] ?? array() ); ?>

			<div id="sentinel-custom-rules-list">
			<?php if ( empty( $custom_rules ) ) : ?>
				<p id="sentinel-no-custom-rules" style="color:#888;"><?php esc_html_e( 'No custom rules yet.', 'wp-sentinel-security' ); ?></p>
			<?php else : ?>
				<?php foreach ( $custom_rules as $idx => $rule ) : ?>
				<div class="sentinel-custom-rule" data-index="<?php echo esc_attr( $idx ); ?>"
					style="border:1px solid #e0e0e0;border-radius:6px;padding:12px 16px;margin-bottom:10px;background:#fafafa;display:grid;grid-template-columns:1fr auto auto;gap:10px;align-items:start;">
					<div>
						<div style="font-weight:600;margin-bottom:4px;"><?php echo esc_html( $rule['id'] ); ?></div>
						<code style="font-size:0.85em;word-break:break-all;"><?php echo esc_html( $rule['pattern'] ); ?></code>
						<div style="font-size:0.8em;color:#777;margin-top:4px;">
							<?php echo esc_html( $rule['description'] ); ?>
							&nbsp;|&nbsp;
							<span style="text-transform:capitalize;"><?php echo esc_html( $rule['severity'] ); ?></span>
						</div>
					</div>
					<input type="hidden"
						name="sentinel_settings[waf_custom_rules][<?php echo esc_attr( $idx ); ?>][id]"
						value="<?php echo esc_attr( $rule['id'] ); ?>">
					<input type="hidden"
						name="sentinel_settings[waf_custom_rules][<?php echo esc_attr( $idx ); ?>][pattern]"
						value="<?php echo esc_attr( $rule['pattern'] ); ?>">
					<input type="hidden"
						name="sentinel_settings[waf_custom_rules][<?php echo esc_attr( $idx ); ?>][description]"
						value="<?php echo esc_attr( $rule['description'] ); ?>">
					<input type="hidden"
						name="sentinel_settings[waf_custom_rules][<?php echo esc_attr( $idx ); ?>][severity]"
						value="<?php echo esc_attr( $rule['severity'] ); ?>">
				</div>
				<?php endforeach; ?>
			<?php endif; ?>
			</div>

			<!-- Add new custom rule form -->
			<div style="border-top:1px solid #e0e0e0;margin-top:16px;padding-top:16px;">
				<h3 style="margin:0 0 12px;"><?php esc_html_e( 'Add New Rule', 'wp-sentinel-security' ); ?></h3>
				<div id="sentinel-rule-notice" style="display:none;margin-bottom:12px;" class="notice"></div>
				<table class="form-table" style="margin:0;">
					<tr>
						<th><label for="new-rule-id"><?php esc_html_e( 'Rule ID', 'wp-sentinel-security' ); ?></label></th>
						<td>
							<input id="new-rule-id" type="text" class="regular-text" placeholder="custom-sqli-hex">
							<p class="description"><?php esc_html_e( 'Unique slug, lowercase with hyphens.', 'wp-sentinel-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><label for="new-rule-pattern"><?php esc_html_e( 'Regex Pattern', 'wp-sentinel-security' ); ?></label></th>
						<td>
							<input id="new-rule-pattern" type="text" class="large-text code" placeholder="/0x[0-9a-f]{8,}/i">
							<p class="description"><?php esc_html_e( 'PHP-compatible regex, including delimiters and flags. Example: /evil-pattern/i', 'wp-sentinel-security' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><label for="new-rule-desc"><?php esc_html_e( 'Description', 'wp-sentinel-security' ); ?></label></th>
						<td><input id="new-rule-desc" type="text" class="large-text" placeholder="<?php esc_attr_e( 'Short description of what this rule detects', 'wp-sentinel-security' ); ?>"></td>
					</tr>
					<tr>
						<th><label for="new-rule-severity"><?php esc_html_e( 'Severity', 'wp-sentinel-security' ); ?></label></th>
						<td>
							<select id="new-rule-severity">
								<option value="critical"><?php esc_html_e( 'Critical', 'wp-sentinel-security' ); ?></option>
								<option value="high"><?php esc_html_e( 'High', 'wp-sentinel-security' ); ?></option>
								<option value="medium" selected><?php esc_html_e( 'Medium', 'wp-sentinel-security' ); ?></option>
								<option value="low"><?php esc_html_e( 'Low', 'wp-sentinel-security' ); ?></option>
							</select>
						</td>
					</tr>
					<tr>
						<th><label for="new-rule-test-input"><?php esc_html_e( 'Test Input', 'wp-sentinel-security' ); ?></label></th>
						<td>
							<input id="new-rule-test-input" type="text" class="large-text code"
								placeholder="<?php esc_attr_e( 'Paste a sample payload to test the regex before saving', 'wp-sentinel-security' ); ?>">
						</td>
					</tr>
				</table>
				<div style="margin-top:12px;display:flex;gap:10px;">
					<button type="button" id="btn-test-rule" class="button button-secondary">
						&#10003; <?php esc_html_e( 'Test Regex', 'wp-sentinel-security' ); ?>
					</button>
					<button type="button" id="btn-add-rule" class="button button-primary">
						+ <?php esc_html_e( 'Add Rule', 'wp-sentinel-security' ); ?>
					</button>
				</div>
			</div>
		</div>

		<script>
		(function($){
			'use strict';

			var ruleCount = <?php echo (int) count( $custom_rules ); ?>;
			var ajaxUrl   = '<?php echo esc_js( admin_url( 'admin-ajax.php' ) ); ?>';
			var testNonce = '<?php echo esc_js( wp_create_nonce( 'sentinel_test_waf_rule' ) ); ?>';

			function ruleNotice( msg, type ) {
				$('#sentinel-rule-notice')
					.removeClass('notice-success notice-error notice-warning')
					.addClass('notice notice-' + type)
					.html('<p>' + msg + '</p>')
					.show();
			}

			// Test button: validate regex via AJAX against the test input.
			$('#btn-test-rule').on('click', function() {
				var pattern = $.trim( $('#new-rule-pattern').val() );
				var input   = $('#new-rule-test-input').val();
				if ( ! pattern ) {
					ruleNotice( '<?php echo esc_js( __( 'Enter a regex pattern first.', 'wp-sentinel-security' ) ); ?>', 'error' );
					return;
				}
				$.post( ajaxUrl, {
					action:  'sentinel_test_waf_rule',
					nonce:   testNonce,
					pattern: pattern,
					input:   input,
				}, function(r) {
					if ( r.success ) {
						var matched = r.data.matched;
						if ( input.length > 0 ) {
							ruleNotice(
								matched
									? '<?php echo esc_js( __( '✓ Regex is valid and matched the test input.', 'wp-sentinel-security' ) ); ?>'
									: '<?php echo esc_js( __( '⚠ Regex is valid but did NOT match the test input.', 'wp-sentinel-security' ) ); ?>',
								matched ? 'success' : 'warning'
							);
						} else {
							ruleNotice( '<?php echo esc_js( __( '✓ Regex syntax is valid.', 'wp-sentinel-security' ) ); ?>', 'success' );
						}
					} else {
						ruleNotice( r.data.message || '<?php echo esc_js( __( 'Invalid regex.', 'wp-sentinel-security' ) ); ?>', 'error' );
					}
				}).fail(function(){
					ruleNotice( '<?php echo esc_js( __( 'Request failed.', 'wp-sentinel-security' ) ); ?>', 'error' );
				});
			});

			// Add rule button: inject hidden inputs + preview card.
			$('#btn-add-rule').on('click', function() {
				var id       = $.trim( $('#new-rule-id').val() );
				var pattern  = $.trim( $('#new-rule-pattern').val() );
				var desc     = $.trim( $('#new-rule-desc').val() );
				var severity = $('#new-rule-severity').val();

				if ( ! id || ! pattern || ! desc ) {
					ruleNotice( '<?php echo esc_js( __( 'Rule ID, Pattern and Description are all required.', 'wp-sentinel-security' ) ); ?>', 'error' );
					return;
				}
				if ( ! /^[a-z0-9-]+$/.test(id) ) {
					ruleNotice( '<?php echo esc_js( __( 'Rule ID must be lowercase letters, numbers and hyphens only.', 'wp-sentinel-security' ) ); ?>', 'error' );
					return;
				}

				$('#sentinel-no-custom-rules').remove();

				var idx  = ruleCount++;
				var html =
					'<div class="sentinel-custom-rule" data-index="' + idx + '" ' +
					'style="border:1px solid #e0e0e0;border-radius:6px;padding:12px 16px;margin-bottom:10px;background:#fafafa;display:grid;grid-template-columns:1fr auto;gap:10px;align-items:start;">' +
					'<div>' +
					'<div style="font-weight:600;margin-bottom:4px;">' + $('<span>').text(id).html() + '</div>' +
					'<code style="font-size:0.85em;word-break:break-all;">' + $('<span>').text(pattern).html() + '</code>' +
					'<div style="font-size:0.8em;color:#777;margin-top:4px;">' + $('<span>').text(desc).html() + ' | ' + $('<span>').text(severity).html() + '</div>' +
					'</div>' +
					'<button type="button" class="button button-small btn-delete-custom-rule" style="color:#c62828;border-color:#c62828;">' +
					'<?php echo esc_js( __( 'Remove', 'wp-sentinel-security' ) ); ?></button>' +
					'<input type="hidden" name="sentinel_settings[waf_custom_rules][' + idx + '][id]"          value="' + $('<span>').text(id).html()       + '">' +
					'<input type="hidden" name="sentinel_settings[waf_custom_rules][' + idx + '][pattern]"     value="' + $('<span>').text(pattern).html()  + '">' +
					'<input type="hidden" name="sentinel_settings[waf_custom_rules][' + idx + '][description]" value="' + $('<span>').text(desc).html()     + '">' +
					'<input type="hidden" name="sentinel_settings[waf_custom_rules][' + idx + '][severity]"    value="' + $('<span>').text(severity).html() + '">' +
					'</div>';

				$('#sentinel-custom-rules-list').append(html);

				// Clear form.
				$('#new-rule-id, #new-rule-pattern, #new-rule-desc, #new-rule-test-input').val('');
				$('#new-rule-severity').val('medium');
				$('#sentinel-rule-notice').hide();
				ruleNotice( '<?php echo esc_js( __( 'Rule added. Save Settings to persist.', 'wp-sentinel-security' ) ); ?>', 'success' );
			});

			// Delete rule button.
			$(document).on('click', '.btn-delete-custom-rule', function(){
				$(this).closest('.sentinel-custom-rule').remove();
				if ( ! $('.sentinel-custom-rule').length ) {
					$('#sentinel-custom-rules-list').html('<p id="sentinel-no-custom-rules" style="color:#888;"><?php echo esc_js( __( 'No custom rules yet.', 'wp-sentinel-security' ) ); ?></p>');
				}
			});

		}(jQuery));
		</script>

		<?php submit_button( __( 'Save Settings', 'wp-sentinel-security' ) ); ?>

</form>

<script>
(function($){
	$('#sentinel-run-now-btn').on('click', function(){
		var $btn = $(this).prop('disabled', true);
		var $st  = $('#sentinel-run-now-status').text('Scheduling…');
		$.post(ajaxurl, {
			action: 'sentinel_run_cron_now',
			nonce:  '<?php echo esc_js( wp_create_nonce( 'sentinel_run_cron_now' ) ); ?>'
		}, function(r){
			$btn.prop('disabled', false);
			$st.text( r.success ? '✓ Scan queued — results will appear in Scanner shortly.' : '✗ ' + (r.data && r.data.message ? r.data.message : 'Error') );
		}).fail(function(){ $btn.prop('disabled', false); $st.text('Request failed.'); });
	});
}(jQuery));
</script>

</div>
