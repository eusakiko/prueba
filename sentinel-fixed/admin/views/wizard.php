<?php
/**
 * Security Setup Wizard — 5-step initial configuration guide.
 *
 * Shown on first activation and accessible later from Settings.
 *
 * @package WP_Sentinel_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$current_step = isset( $_GET['step'] ) ? absint( $_GET['step'] ) : 1;  // phpcs:ignore WordPress.Security.NonceVerification.Recommended
$current_step = max( 1, min( 5, $current_step ) );

$steps = array(
	1 => array(
		'label' => __( 'Initial Scan', 'wp-sentinel-security' ),
		'icon'  => 'dashicons-search',
	),
	2 => array(
		'label' => __( 'Results', 'wp-sentinel-security' ),
		'icon'  => 'dashicons-clipboard',
	),
	3 => array(
		'label' => __( 'Apply Fixes', 'wp-sentinel-security' ),
		'icon'  => 'dashicons-hammer',
	),
	4 => array(
		'label' => __( 'Alerts', 'wp-sentinel-security' ),
		'icon'  => 'dashicons-bell',
	),
	5 => array(
		'label' => __( 'Schedule', 'wp-sentinel-security' ),
		'icon'  => 'dashicons-calendar-alt',
	),
);
?>

<div class="wrap sentinel-wrap sentinel-wizard-wrap">

	<div class="sentinel-page-header">
		<div class="sentinel-header-left">
			<span class="dashicons dashicons-superhero sentinel-header-icon"></span>
			<div>
				<h1><?php esc_html_e( 'Security Setup Wizard', 'wp-sentinel-security' ); ?></h1>
				<p class="description"><?php esc_html_e( 'Complete these steps to secure your WordPress site.', 'wp-sentinel-security' ); ?></p>
			</div>
		</div>
	</div>

	<!-- Step Progress Bar -->
	<div class="sentinel-wizard-steps">
		<?php foreach ( $steps as $num => $step ) : ?>
			<div class="sentinel-wizard-step <?php echo $num === $current_step ? 'active' : ( $num < $current_step ? 'completed' : '' ); ?>">
				<div class="sentinel-wizard-step-circle">
					<?php if ( $num < $current_step ) : ?>
						<span class="dashicons dashicons-yes"></span>
					<?php else : ?>
						<?php echo esc_html( $num ); ?>
					<?php endif; ?>
				</div>
				<div class="sentinel-wizard-step-label"><?php echo esc_html( $step['label'] ); ?></div>
			</div>
			<?php if ( $num < count( $steps ) ) : ?>
				<div class="sentinel-wizard-step-connector <?php echo $num < $current_step ? 'completed' : ''; ?>"></div>
			<?php endif; ?>
		<?php endforeach; ?>
	</div>

	<!-- Step Content -->
	<div class="sentinel-card sentinel-wizard-step-content">

		<?php if ( 1 === $current_step ) : ?>
			<!-- Step 1: Initial Full Scan -->
			<div class="sentinel-wizard-step-body">
				<span class="dashicons dashicons-search sentinel-wizard-step-icon"></span>
				<h2><?php esc_html_e( 'Step 1: Run Your Initial Scan', 'wp-sentinel-security' ); ?></h2>
				<p><?php esc_html_e( 'Let WP Sentinel Security perform a comprehensive scan of your WordPress installation. This checks for vulnerabilities, configuration issues, malware, and more.', 'wp-sentinel-security' ); ?></p>
				<p><?php esc_html_e( 'A full scan takes 2–5 minutes depending on the number of plugins and file count.', 'wp-sentinel-security' ); ?></p>

				<div class="sentinel-wizard-actions">
					<button id="sentinel-wizard-start-scan" class="button button-primary button-hero sentinel-start-scan" data-scan-type="full">
						<span class="dashicons dashicons-search"></span>
						<?php esc_html_e( 'Start Full Scan Now', 'wp-sentinel-security' ); ?>
					</button>
					<a href="<?php echo esc_url( add_query_arg( 'step', 2 ) ); ?>" class="button button-secondary">
						<?php esc_html_e( 'Skip (Use Existing Results)', 'wp-sentinel-security' ); ?>
					</a>
				</div>

				<div id="sentinel-wizard-scan-progress" style="display:none;" class="sentinel-progress-bar-wrap">
					<div class="sentinel-progress-bar"><div class="sentinel-progress-fill" style="width:0%"></div></div>
					<p class="sentinel-scan-status-text"><?php esc_html_e( 'Scanning...', 'wp-sentinel-security' ); ?></p>
				</div>
			</div>

		<?php elseif ( 2 === $current_step ) : ?>
			<!-- Step 2: Results Summary -->
			<div class="sentinel-wizard-step-body">
				<span class="dashicons dashicons-clipboard sentinel-wizard-step-icon"></span>
				<h2><?php esc_html_e( 'Step 2: Review Your Security Results', 'wp-sentinel-security' ); ?></h2>
				<?php
				global $wpdb;
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
				$last_scan = $wpdb->get_row( "SELECT * FROM {$wpdb->prefix}sentinel_scans WHERE status = 'completed' ORDER BY id DESC LIMIT 1" );

				if ( $last_scan ) :
					$summary = json_decode( $last_scan->summary, true );
					?>
					<div class="sentinel-wizard-severity-grid">
						<?php
						$severity_colors = array(
							'critical' => '#d63638',
							'high'     => '#dba617',
							'medium'   => '#f0b429',
							'low'      => '#2271b1',
							'info'     => '#787c82',
						);
						foreach ( array( 'critical', 'high', 'medium', 'low', 'info' ) as $sev ) :
							$count = $summary[ $sev ] ?? 0;
							?>
							<div class="sentinel-severity-badge" style="border-color:<?php echo esc_attr( $severity_colors[ $sev ] ); ?>">
								<span class="sentinel-severity-count" style="color:<?php echo esc_attr( $severity_colors[ $sev ] ); ?>"><?php echo esc_html( $count ); ?></span>
								<span class="sentinel-severity-label"><?php echo esc_html( ucfirst( $sev ) ); ?></span>
							</div>
						<?php endforeach; ?>
					</div>
					<p><?php esc_html_e( 'Proceed to the next step to automatically apply recommended fixes.', 'wp-sentinel-security' ); ?></p>
				<?php else : ?>
					<p class="sentinel-notice-warning">
						<?php esc_html_e( 'No completed scan found. Please go back and run a scan first.', 'wp-sentinel-security' ); ?>
					</p>
				<?php endif; ?>

				<div class="sentinel-wizard-actions">
					<a href="<?php echo esc_url( add_query_arg( 'step', 1 ) ); ?>" class="button button-secondary">&larr; <?php esc_html_e( 'Back', 'wp-sentinel-security' ); ?></a>
					<a href="<?php echo esc_url( add_query_arg( 'step', 3 ) ); ?>" class="button button-primary"><?php esc_html_e( 'Next: Apply Fixes', 'wp-sentinel-security' ); ?> &rarr;</a>
				</div>
			</div>

		<?php elseif ( 3 === $current_step ) : ?>
			<!-- Step 3: Recommended Fixes -->
			<div class="sentinel-wizard-step-body">
				<span class="dashicons dashicons-hammer sentinel-wizard-step-icon"></span>
				<h2><?php esc_html_e( 'Step 3: Apply Recommended Fixes', 'wp-sentinel-security' ); ?></h2>
				<p><?php esc_html_e( 'The following hardening actions are recommended based on your scan results. Click "Apply" to activate each fix.', 'wp-sentinel-security' ); ?></p>

				<div class="sentinel-wizard-fixes">
					<?php
					$fixes = array(
						array(
							'id'          => 'disallow_file_edit',
							'label'       => __( 'Disable File Editor', 'wp-sentinel-security' ),
							'description' => __( 'Prevents editing of theme and plugin files from the admin area.', 'wp-sentinel-security' ),
							'page'        => 'sentinel-hardening',
						),
						array(
							'id'          => 'force_ssl_admin',
							'label'       => __( 'Force HTTPS for Admin', 'wp-sentinel-security' ),
							'description' => __( 'Ensures the admin area is only accessible over HTTPS.', 'wp-sentinel-security' ),
							'page'        => 'sentinel-hardening',
						),
						array(
							'id'          => 'hide_wp_version',
							'label'       => __( 'Hide WordPress Version', 'wp-sentinel-security' ),
							'description' => __( 'Removes the WordPress version number from public pages.', 'wp-sentinel-security' ),
							'page'        => 'sentinel-hardening',
						),
						array(
							'id'          => 'disable_xmlrpc',
							'label'       => __( 'Disable XML-RPC', 'wp-sentinel-security' ),
							'description' => __( 'Disables XML-RPC if you do not use Jetpack or the mobile app.', 'wp-sentinel-security' ),
							'page'        => 'sentinel-hardening',
						),
					);
					foreach ( $fixes as $fix ) :
						?>
						<div class="sentinel-wizard-fix-item">
							<div class="sentinel-wizard-fix-info">
								<strong><?php echo esc_html( $fix['label'] ); ?></strong>
								<p><?php echo esc_html( $fix['description'] ); ?></p>
							</div>
							<a href="<?php echo esc_url( admin_url( 'admin.php?page=' . $fix['page'] ) ); ?>" class="button button-secondary">
								<?php esc_html_e( 'Apply', 'wp-sentinel-security' ); ?>
							</a>
						</div>
					<?php endforeach; ?>
				</div>

				<div class="sentinel-wizard-actions">
					<a href="<?php echo esc_url( add_query_arg( 'step', 2 ) ); ?>" class="button button-secondary">&larr; <?php esc_html_e( 'Back', 'wp-sentinel-security' ); ?></a>
					<a href="<?php echo esc_url( add_query_arg( 'step', 4 ) ); ?>" class="button button-primary"><?php esc_html_e( 'Next: Configure Alerts', 'wp-sentinel-security' ); ?> &rarr;</a>
				</div>
			</div>

		<?php elseif ( 4 === $current_step ) : ?>
			<!-- Step 4: Configure Alert Channels -->
			<div class="sentinel-wizard-step-body">
				<span class="dashicons dashicons-bell sentinel-wizard-step-icon"></span>
				<h2><?php esc_html_e( 'Step 4: Configure Alert Channels', 'wp-sentinel-security' ); ?></h2>
				<p><?php esc_html_e( 'Set up notifications so you are alerted immediately when security events occur.', 'wp-sentinel-security' ); ?></p>

				<div class="sentinel-wizard-alert-channels">
					<?php
					$channels = array(
						'email'    => array( 'label' => __( 'Email', 'wp-sentinel-security' ), 'icon' => 'dashicons-email-alt', 'configured' => ! empty( get_option( 'sentinel_settings', array() )['alert_email'] ) ),
						'slack'    => array( 'label' => __( 'Slack', 'wp-sentinel-security' ), 'icon' => 'dashicons-admin-comments', 'configured' => ! empty( get_option( 'sentinel_settings', array() )['slack_webhook'] ) ),
						'discord'  => array( 'label' => __( 'Discord', 'wp-sentinel-security' ), 'icon' => 'dashicons-format-chat', 'configured' => ! empty( get_option( 'sentinel_settings', array() )['discord_webhook'] ) ),
						'telegram' => array( 'label' => __( 'Telegram', 'wp-sentinel-security' ), 'icon' => 'dashicons-share', 'configured' => ! empty( get_option( 'sentinel_settings', array() )['telegram_bot_token'] ) ),
					);
					foreach ( $channels as $key => $channel ) :
						?>
						<div class="sentinel-wizard-channel <?php echo $channel['configured'] ? 'configured' : ''; ?>">
							<span class="dashicons <?php echo esc_attr( $channel['icon'] ); ?>"></span>
							<span><?php echo esc_html( $channel['label'] ); ?></span>
							<?php if ( $channel['configured'] ) : ?>
								<span class="sentinel-badge-success"><?php esc_html_e( 'Configured', 'wp-sentinel-security' ); ?></span>
							<?php else : ?>
								<a href="<?php echo esc_url( admin_url( 'admin.php?page=sentinel-settings&tab=alerts' ) ); ?>" class="button button-small"><?php esc_html_e( 'Set Up', 'wp-sentinel-security' ); ?></a>
							<?php endif; ?>
						</div>
					<?php endforeach; ?>
				</div>

				<div class="sentinel-wizard-actions">
					<a href="<?php echo esc_url( add_query_arg( 'step', 3 ) ); ?>" class="button button-secondary">&larr; <?php esc_html_e( 'Back', 'wp-sentinel-security' ); ?></a>
					<a href="<?php echo esc_url( add_query_arg( 'step', 5 ) ); ?>" class="button button-primary"><?php esc_html_e( 'Next: Set Schedule', 'wp-sentinel-security' ); ?> &rarr;</a>
				</div>
			</div>

		<?php elseif ( 5 === $current_step ) : ?>
			<!-- Step 5: Scan Schedule -->
			<div class="sentinel-wizard-step-body">
				<span class="dashicons dashicons-calendar-alt sentinel-wizard-step-icon"></span>
				<h2><?php esc_html_e( 'Step 5: Set Scan Schedule', 'wp-sentinel-security' ); ?></h2>
				<p><?php esc_html_e( 'Automated scans keep you protected around the clock. Choose your preferred scan frequency.', 'wp-sentinel-security' ); ?></p>

				<form method="post" action="options.php">
					<?php settings_fields( 'sentinel_settings_group' ); ?>
					<input type="hidden" name="sentinel_settings[wizard_completed]" value="1" />

					<div class="sentinel-wizard-schedule-options">
						<?php
						$current_freq = get_option( 'sentinel_settings', array() )['scan_frequency'] ?? 'daily';
						$options      = array(
							'hourly'  => __( 'Hourly', 'wp-sentinel-security' ),
							'daily'   => __( 'Daily (Recommended)', 'wp-sentinel-security' ),
							'weekly'  => __( 'Weekly', 'wp-sentinel-security' ),
							'monthly' => __( 'Monthly', 'wp-sentinel-security' ),
						);
						foreach ( $options as $value => $label ) :
							?>
							<label class="sentinel-wizard-schedule-option <?php echo $current_freq === $value ? 'selected' : ''; ?>">
								<input type="radio" name="sentinel_settings[scan_frequency]"
									value="<?php echo esc_attr( $value ); ?>"
									<?php checked( $current_freq, $value ); ?> />
								<?php echo esc_html( $label ); ?>
							</label>
						<?php endforeach; ?>
					</div>

					<div class="sentinel-wizard-actions">
						<a href="<?php echo esc_url( add_query_arg( 'step', 4 ) ); ?>" class="button button-secondary">&larr; <?php esc_html_e( 'Back', 'wp-sentinel-security' ); ?></a>
						<button type="submit" class="button button-primary button-hero">
							<span class="dashicons dashicons-yes-alt"></span>
							<?php esc_html_e( 'Complete Setup', 'wp-sentinel-security' ); ?>
						</button>
					</div>
				</form>

				<div class="sentinel-wizard-complete-links" style="margin-top:1.5em;text-align:center;">
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-sentinel-security' ) ); ?>" class="button button-link">
						<?php esc_html_e( '→ Go to Dashboard', 'wp-sentinel-security' ); ?>
					</a>
				</div>
			</div>

		<?php endif; ?>

	</div><!-- .sentinel-wizard-step-content -->

</div><!-- .sentinel-wizard-wrap -->

<style>
.sentinel-wizard-wrap { max-width: 900px; }
.sentinel-wizard-steps { display: flex; align-items: center; margin: 1.5em 0 2em; }
.sentinel-wizard-step { display: flex; flex-direction: column; align-items: center; gap: 0.4em; min-width: 80px; }
.sentinel-wizard-step-circle { width: 36px; height: 36px; border-radius: 50%; background: #ccc; color: #fff; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 14px; }
.sentinel-wizard-step.active .sentinel-wizard-step-circle { background: #2271b1; }
.sentinel-wizard-step.completed .sentinel-wizard-step-circle { background: #00a32a; }
.sentinel-wizard-step-label { font-size: 11px; color: #555; text-align: center; }
.sentinel-wizard-step-connector { flex: 1; height: 2px; background: #ccc; margin: 0 4px; margin-bottom: 18px; }
.sentinel-wizard-step-connector.completed { background: #00a32a; }
.sentinel-wizard-step-body { text-align: center; padding: 2em; }
.sentinel-wizard-step-icon { font-size: 48px; width: 48px; height: 48px; color: #2271b1; margin-bottom: 0.5em; display: block; }
.sentinel-wizard-actions { display: flex; gap: 1em; justify-content: center; margin-top: 2em; }
.sentinel-wizard-severity-grid { display: flex; gap: 1em; justify-content: center; margin: 1.5em 0; flex-wrap: wrap; }
.sentinel-severity-badge { border: 2px solid; border-radius: 8px; padding: 1em 1.5em; min-width: 80px; text-align: center; }
.sentinel-severity-count { display: block; font-size: 2em; font-weight: 700; }
.sentinel-severity-label { font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; }
.sentinel-wizard-fixes { text-align: left; margin: 1.5em 0; }
.sentinel-wizard-fix-item { display: flex; align-items: center; justify-content: space-between; padding: 1em; border: 1px solid #e0e0e0; border-radius: 6px; margin-bottom: 0.75em; background: #fafafa; }
.sentinel-wizard-fix-info p { margin: 0.25em 0 0; color: #555; font-size: 13px; }
.sentinel-wizard-alert-channels { display: flex; gap: 1em; justify-content: center; flex-wrap: wrap; margin: 1.5em 0; }
.sentinel-wizard-channel { display: flex; flex-direction: column; align-items: center; gap: 0.5em; padding: 1.5em; border: 1px solid #e0e0e0; border-radius: 8px; min-width: 100px; background: #fafafa; }
.sentinel-wizard-channel.configured { border-color: #00a32a; background: #f0faf0; }
.sentinel-badge-success { background: #00a32a; color: #fff; padding: 2px 8px; border-radius: 4px; font-size: 11px; }
.sentinel-wizard-schedule-options { display: flex; gap: 1em; justify-content: center; flex-wrap: wrap; margin: 1.5em 0; }
.sentinel-wizard-schedule-option { padding: 1em 1.5em; border: 2px solid #e0e0e0; border-radius: 8px; cursor: pointer; transition: all 0.2s; }
.sentinel-wizard-schedule-option input { margin-right: 0.5em; }
.sentinel-wizard-schedule-option.selected { border-color: #2271b1; background: #f0f6ff; }
.sentinel-notice-warning { background: #fff8e5; border-left: 4px solid #dba617; padding: 1em; border-radius: 0 4px 4px 0; }
</style>
