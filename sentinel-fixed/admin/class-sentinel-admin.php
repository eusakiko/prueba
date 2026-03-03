<?php
/**
 * Admin class.
 *
 * Handles menu registration, asset enqueuing, settings, and page rendering.
 *
 * @package WP_Sentinel_Security
 * @since   1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Sentinel_Admin
 */
class Sentinel_Admin {

	/**
	 * Plugin settings.
	 *
	 * @var array
	 */
	private $settings;

	/**
	 * Constructor.
	 *
	 * @param array $settings Plugin settings.
	 */
	public function __construct( $settings = array() ) {
		$this->settings = $settings;
	}

	/**
	 * Register admin hooks.
	 *
	 * @return void
	 */
	public function register() {
		add_action( 'admin_menu', array( $this, 'register_menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_filter( 'plugin_action_links_' . SENTINEL_PLUGIN_BASENAME, array( $this, 'add_plugin_links' ) );

		// Admin bar badge for critical/high vulnerabilities.
		add_action( 'admin_bar_menu',    array( $this, 'add_bar_badge' ), 100 );
		add_action( 'wp_enqueue_scripts', array( $this, 'enqueue_bar_badge_styles' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_bar_badge_styles' ) );

		// Activity log AJAX handlers.
		add_action( 'wp_ajax_sentinel_export_activity_log', array( $this, 'ajax_export_activity_log' ) );
		add_action( 'wp_ajax_sentinel_clear_old_logs',      array( $this, 'ajax_clear_old_logs' ) );

		// Language switcher AJAX handler.
		add_action( 'wp_ajax_sentinel_switch_language', array( $this, 'ajax_switch_language' ) );

		// Vulnerability management AJAX handlers.
		add_action( 'wp_ajax_sentinel_mark_vulnerability',       array( $this, 'ajax_mark_vulnerability' ) );
		add_action( 'wp_ajax_sentinel_get_vulnerability',        array( $this, 'ajax_get_vulnerability' ) );
		add_action( 'wp_ajax_sentinel_bulk_mark_vulnerability',  array( $this, 'ajax_bulk_mark_vulnerability' ) );

		// Firewall IP management AJAX handlers.
		add_action( 'wp_ajax_sentinel_block_ip',        array( $this, 'ajax_block_ip' ) );
		add_action( 'wp_ajax_sentinel_unblock_ip',      array( $this, 'ajax_unblock_ip' ) );
		add_action( 'wp_ajax_sentinel_whitelist_ip',    array( $this, 'ajax_whitelist_ip' ) );
		add_action( 'wp_ajax_sentinel_unwhitelist_ip',  array( $this, 'ajax_unwhitelist_ip' ) );

		// Scheduled scan: trigger immediately from Settings.
		add_action( 'wp_ajax_sentinel_run_cron_now', array( $this, 'ajax_run_cron_now' ) );

		// WAF custom rule test.
		add_action( 'wp_ajax_sentinel_test_waf_rule', array( $this, 'ajax_test_waf_rule' ) );

		// Security Headers: emit on every front-end + admin request.
		add_action( 'send_headers', array( $this, 'emit_security_headers' ), 5 );

		// Last Logins: register login tracking hooks.
		add_action( 'init', array( $this, 'register_last_logins_hooks' ), 1 );

		// Vulnerability CSV export.
		add_action( 'wp_ajax_sentinel_export_vulnerabilities', array( $this, 'ajax_export_vulnerabilities' ) );

		// Backup download via admin-post.
		add_action( 'admin_post_sentinel_download_backup', array( $this, 'handle_download_backup' ) );
	}

	/**
	 * Register admin menu and submenus.
	 *
	 * @return void
	 */
	public function register_menu() {
		add_menu_page(
			__( 'Sentinel Security', 'wp-sentinel-security' ),
			__( 'Sentinel Security', 'wp-sentinel-security' ),
			'manage_options',
			'sentinel-security',
			array( $this, 'render_dashboard' ),
			'dashicons-shield-alt',
			3
		);

		$submenus = array(
			array(
				'parent' => 'sentinel-security',
				'title'  => __( 'Dashboard', 'wp-sentinel-security' ),
				'menu'   => __( 'Dashboard', 'wp-sentinel-security' ),
				'slug'   => 'sentinel-security',
				'cb'     => array( $this, 'render_dashboard' ),
			),
			array(
				'parent' => 'sentinel-security',
				'title'  => __( 'Scanner', 'wp-sentinel-security' ),
				'menu'   => __( 'Scanner', 'wp-sentinel-security' ),
				'slug'   => 'sentinel-scanner',
				'cb'     => array( $this, 'render_scanner' ),
			),
			array(
				'parent' => 'sentinel-security',
				'title'  => __( 'Firewall', 'wp-sentinel-security' ),
				'menu'   => __( 'Firewall', 'wp-sentinel-security' ),
				'slug'   => 'sentinel-firewall',
				'cb'     => array( $this, 'render_firewall' ),
			),
			array(
				'parent' => 'sentinel-security',
				'title'  => __( 'Hardening', 'wp-sentinel-security' ),
				'menu'   => __( 'Hardening', 'wp-sentinel-security' ),
				'slug'   => 'sentinel-hardening',
				'cb'     => array( $this, 'render_hardening' ),
			),
			array(
				'parent' => 'sentinel-security',
				'title'  => __( 'Backups', 'wp-sentinel-security' ),
				'menu'   => __( 'Backups', 'wp-sentinel-security' ),
				'slug'   => 'sentinel-backups',
				'cb'     => array( $this, 'render_backups' ),
			),
			array(
				'parent' => 'sentinel-security',
				'title'  => __( 'Reports', 'wp-sentinel-security' ),
				'menu'   => __( 'Reports', 'wp-sentinel-security' ),
				'slug'   => 'sentinel-reports',
				'cb'     => array( $this, 'render_reports' ),
			),
			array(
				'parent' => 'sentinel-security',
				'title'  => __( 'Alerts', 'wp-sentinel-security' ),
				'menu'   => __( 'Alerts', 'wp-sentinel-security' ),
				'slug'   => 'sentinel-alerts',
				'cb'     => array( $this, 'render_alerts' ),
			),
			array(
				'parent' => 'sentinel-security',
				'title'  => __( 'Activity Log', 'wp-sentinel-security' ),
				'menu'   => __( 'Activity', 'wp-sentinel-security' ),
				'slug'   => 'sentinel-activity',
				'cb'     => array( $this, 'render_activity' ),
			),
			array(
				'parent' => 'sentinel-security',
				'title'  => __( 'Last Logins', 'wp-sentinel-security' ),
				'menu'   => __( 'Last Logins', 'wp-sentinel-security' ),
				'slug'   => 'sentinel-lastlogins',
				'cb'     => array( $this, 'render_lastlogins' ),
			),
			array(
				'parent' => 'sentinel-security',
				'title'  => __( 'Security Headers', 'wp-sentinel-security' ),
				'menu'   => __( 'Headers', 'wp-sentinel-security' ),
				'slug'   => 'sentinel-headers',
				'cb'     => array( $this, 'render_headers' ),
			),
			array(
				'parent' => 'sentinel-security',
				'title'  => __( 'Recommendations', 'wp-sentinel-security' ),
				'menu'   => __( 'Recommendations', 'wp-sentinel-security' ),
				'slug'   => 'sentinel-recommendations',
				'cb'     => array( $this, 'render_recommendations' ),
			),
			array(
				'parent' => 'sentinel-security',
				'title'  => __( 'Intelligence', 'wp-sentinel-security' ),
				'menu'   => __( 'Intelligence', 'wp-sentinel-security' ),
				'slug'   => 'sentinel-intelligence',
				'cb'     => array( $this, 'render_intelligence' ),
			),
			array(
				'parent' => 'sentinel-security',
				'title'  => __( 'Settings', 'wp-sentinel-security' ),
				'menu'   => __( 'Settings', 'wp-sentinel-security' ),
				'slug'   => 'sentinel-settings',
				'cb'     => array( $this, 'render_settings' ),
			),
			array(
				'parent' => 'sentinel-security',
				'title'  => __( 'Setup Wizard', 'wp-sentinel-security' ),
				'menu'   => __( 'Setup Wizard', 'wp-sentinel-security' ),
				'slug'   => 'sentinel-wizard',
				'cb'     => array( $this, 'render_wizard' ),
			),
		);

		foreach ( $submenus as $submenu ) {
			add_submenu_page(
				$submenu['parent'],
				$submenu['title'],
				$submenu['menu'],
				'manage_options',
				$submenu['slug'],
				$submenu['cb']
			);
		}
	}

	/**
	 * Enqueue admin assets.
	 *
	 * @param string $hook Current admin page hook.
	 * @return void
	 */
	public function enqueue_assets( $hook ) {
		// Only load on sentinel pages.
		if ( false === strpos( $hook, 'sentinel' ) ) {
			return;
		}

		// CSS.
		wp_enqueue_style(
			'sentinel-admin',
			SENTINEL_PLUGIN_URL . 'admin/css/sentinel-admin.css',
			array(),
			SENTINEL_VERSION
		);

		wp_enqueue_style(
			'sentinel-dashboard',
			SENTINEL_PLUGIN_URL . 'admin/css/sentinel-dashboard.css',
			array( 'sentinel-admin' ),
			SENTINEL_VERSION
		);

		// Reports CSS.
		wp_enqueue_style(
			'sentinel-reports',
			SENTINEL_PLUGIN_URL . 'admin/css/sentinel-reports.css',
			array( 'sentinel-admin' ),
			SENTINEL_VERSION
		);

		// Intelligence JS.
		wp_enqueue_script(
			'sentinel-intelligence',
			SENTINEL_PLUGIN_URL . 'admin/js/sentinel-intelligence.js',
			array( 'sentinel-admin' ),
			SENTINEL_VERSION,
			true
		);

		// Chart.js — prefer local vendor copy, fall back to CDN.
		$local_chartjs = SENTINEL_PLUGIN_DIR . 'admin/js/vendor/chart.umd.min.js';
		if ( file_exists( $local_chartjs ) ) {
			$chartjs_url = SENTINEL_PLUGIN_URL . 'admin/js/vendor/chart.umd.min.js';
		} else {
			$chartjs_url = 'https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js';
		}
		wp_enqueue_script(
			'chartjs',
			$chartjs_url,
			array(),
			'4.4.0',
			true
		);

		// Plugin JS.
		wp_enqueue_script(
			'sentinel-admin',
			SENTINEL_PLUGIN_URL . 'admin/js/sentinel-admin.js',
			array( 'jquery', 'chartjs' ),
			SENTINEL_VERSION,
			true
		);

		wp_enqueue_script(
			'sentinel-scanner',
			SENTINEL_PLUGIN_URL . 'admin/js/sentinel-scanner.js',
			array( 'sentinel-admin' ),
			SENTINEL_VERSION,
			true
		);

		// Localize script data.
		wp_localize_script(
			'sentinel-admin',
			'sentinelData',
			array(
				'ajaxUrl'      => admin_url( 'admin-ajax.php' ),
				'restUrl'      => rest_url( 'sentinel/v1/' ),
				'updateUrl'    => admin_url( 'update-core.php' ),
				'hardeningUrl' => admin_url( 'admin.php?page=sentinel-hardening' ),
				'nonces'   => array(
					'sentinel'     => wp_create_nonce( 'sentinel_nonce' ),         // BUG FIX: activity log export/clear handlers need this.
					'scan'         => wp_create_nonce( 'sentinel_scan_nonce' ),
					'backup'       => wp_create_nonce( 'sentinel_backup_nonce' ),
					'restore'      => wp_create_nonce( 'sentinel_restore_nonce' ),
					'delete'       => wp_create_nonce( 'sentinel_delete_nonce' ),
					'intelligence' => wp_create_nonce( 'sentinel_intelligence_nonce' ),
					'hardening'    => wp_create_nonce( 'sentinel_hardening_nonce' ),
					'report'       => wp_create_nonce( 'sentinel_report_nonce' ),
					'alert'        => wp_create_nonce( 'sentinel_alert_nonce' ),
					'rest'         => wp_create_nonce( 'wp_rest' ), // BUG FIX: REST API nonce.
				),
				'i18n'     => array(
					'scanning'           => __( 'Scanning...', 'wp-sentinel-security' ),
					'scanComplete'       => __( 'Scan complete!', 'wp-sentinel-security' ),
					'scanCompleteNext'   => __( 'What to do next: review the findings below and address critical issues first.', 'wp-sentinel-security' ),
					'scanFailed'         => __( 'Scan failed. Please try again.', 'wp-sentinel-security' ),
					'backupCreating'     => __( 'Creating backup...', 'wp-sentinel-security' ),
					'backupComplete'     => __( 'Backup created successfully!', 'wp-sentinel-security' ),
					'backupCompleteNext' => __( 'What to do next: you can safely apply security changes now.', 'wp-sentinel-security' ),
					'backupFailed'       => __( 'Backup failed. Please try again.', 'wp-sentinel-security' ),
					'backupDeleted'      => __( 'Backup deleted successfully.', 'wp-sentinel-security' ),
					'confirmDelete'      => __( 'Are you sure you want to delete this backup? This action cannot be undone.', 'wp-sentinel-security' ),
					'confirmRestore'     => __( 'Are you sure you want to restore this backup? Your current data will be replaced.', 'wp-sentinel-security' ),
					'cancel'             => __( 'Cancel', 'wp-sentinel-security' ),
					'noVulnerabilities'  => __( 'No vulnerabilities found.', 'wp-sentinel-security' ),
					'urgencyCritical'    => __( 'Critical (Do today)', 'wp-sentinel-security' ),
					'urgencyHigh'        => __( 'High (Within 48h)', 'wp-sentinel-security' ),
					'urgencyMedium'      => __( 'Medium (This week)', 'wp-sentinel-security' ),
					'urgencyLow'         => __( 'Low (Monitor)', 'wp-sentinel-security' ),
					'urgencyInfo'        => __( 'Info', 'wp-sentinel-security' ),
					'fixNow'             => __( 'Fix now', 'wp-sentinel-security' ),
					'viewGuide'          => __( 'View guide', 'wp-sentinel-security' ),
					'viewResults'        => __( 'View Results', 'wp-sentinel-security' ),
					'viewCve'            => __( 'View CVE on NVD', 'wp-sentinel-security' ),
					'whatThisMeans'      => __( 'What this means:', 'wp-sentinel-security' ),
					'whatToDoNext'       => __( 'What to do next:', 'wp-sentinel-security' ),
					'detailsUnavailable' => __( 'Details not available.', 'wp-sentinel-security' ),
					'securityScore'      => __( 'Security Score', 'wp-sentinel-security' ),
					'scanType'           => __( 'Type', 'wp-sentinel-security' ),
					'scanDate'           => __( 'Date', 'wp-sentinel-security' ),
					'issuesFound'        => __( 'Issues found', 'wp-sentinel-security' ),
					'alertSent'          => __( 'Test alert sent successfully.', 'wp-sentinel-security' ),
					'alertFailed'        => __( 'Alert could not be sent. Check your email settings in WordPress or configure SMTP.', 'wp-sentinel-security' ),
					// Vulnerability management.
					'ignore'             => __( 'Ignore', 'wp-sentinel-security' ),
					'markFp'             => __( 'False positive', 'wp-sentinel-security' ),
					'reopen'             => __( 'Reopen', 'wp-sentinel-security' ),
					'markedIgnored'      => __( 'Ignored', 'wp-sentinel-security' ),
					'markedFp'           => __( 'False positive', 'wp-sentinel-security' ),
					'statusUpdated'      => __( 'Status updated.', 'wp-sentinel-security' ),
					'actionFailed'       => __( 'Action failed. Please try again.', 'wp-sentinel-security' ),
					'selectAction'       => __( 'Please select an action first.', 'wp-sentinel-security' ),
					'selectItems'        => __( 'Please select at least one item.', 'wp-sentinel-security' ),
					'loading'            => __( 'Loading...', 'wp-sentinel-security' ),
					'references'         => __( 'References', 'wp-sentinel-security' ),
				),
				'scoreHistory' => Scoring_Engine::get_score_history( 30 ),
				'vulnCounts'   => Scoring_Engine::calculate_site_score()['by_severity'],
				'currentLang'  => get_option( 'sentinel_language', '' ),
				'languages'    => array(
					''      => __( 'English (default)', 'wp-sentinel-security' ),
					'es_ES' => __( 'Español', 'wp-sentinel-security' ),
					'fr_FR' => __( 'Français', 'wp-sentinel-security' ),
					'de_DE' => __( 'Deutsch', 'wp-sentinel-security' ),
					'pt_BR' => __( 'Português (Brasil)', 'wp-sentinel-security' ),
					'it_IT' => __( 'Italiano', 'wp-sentinel-security' ),
				),
			)
		);
	}

	/**
	 * Register plugin settings.
	 *
	 * @return void
	 */
	public function register_settings() {
		register_setting(
			'sentinel_settings_group',
			'sentinel_settings',
			array( $this, 'sanitize_settings' )
		);
	}

	/**
	 * Sanitize settings before saving.
	 *
	 * @param array $input Raw settings input.
	 * @return array Sanitized settings.
	 */
	public function sanitize_settings( $input ) {
		$output = array();

		$output['scan_frequency']       = in_array( $input['scan_frequency'] ?? '', array( 'hourly', 'twicedaily', 'daily', 'weekly', 'monthly' ), true )
			? $input['scan_frequency']
			: 'daily';
		$output['scheduled_scan_type']  = in_array( $input['scheduled_scan_type'] ?? '', array( 'quick', 'full' ), true )
			? $input['scheduled_scan_type']
			: 'quick';
		$output['backup_before_action'] = ! empty( $input['backup_before_action'] );
		$output['alert_email']          = sanitize_email( $input['alert_email'] ?? '' );
		$output['alert_channels']       = array_map( 'sanitize_text_field', (array) ( $input['alert_channels'] ?? array( 'email' ) ) );
		$output['scoring_method']       = 'cvss_v3';
		$output['log_retention_days']   = max( 1, absint( $input['log_retention_days'] ?? 90 ) );
		$output['async_scanning']       = ! empty( $input['async_scanning'] );
		$output['login_max_attempts']   = max( 1, min( 100,  absint( $input['login_max_attempts']  ?? 5  ) ) );
		$output['login_lockout_mins']   = max( 1, min( 1440, absint( $input['login_lockout_mins']  ?? 15 ) ) );
		$output['rate_limit_enabled']   = ! empty( $input['rate_limit_enabled'] );
		$output['rate_limit_requests']  = max( 1, min( 10000, absint( $input['rate_limit_requests'] ?? 120 ) ) );
		$output['rate_limit_window']    = max( 1, min( 3600,  absint( $input['rate_limit_window']   ?? 60  ) ) );
		$raw_wl = $input['rate_limit_whitelist_raw'] ?? '';
		$output['rate_limit_whitelist'] = array_values( array_filter( array_map( 'sanitize_text_field', explode( "\n", $raw_wl ) ) ) );
		$output['wpscan_api_key']             = sanitize_text_field( $input['wpscan_api_key'] ?? '' );
		$output['google_safe_browsing_key']   = sanitize_text_field( $input['google_safe_browsing_key'] ?? '' );
		$output['slack_webhook']        = esc_url_raw( $input['slack_webhook'] ?? '' );
		$output['telegram_bot_token']   = sanitize_text_field( $input['telegram_bot_token'] ?? '' );
		$output['telegram_chat_id']     = sanitize_text_field( $input['telegram_chat_id'] ?? '' );
		$output['company_name']         = sanitize_text_field( $input['company_name'] ?? '' );
		$output['company_logo']         = esc_url_raw( $input['company_logo'] ?? '' );

		// 2FA settings.
		$output['2fa_enabled']        = ! empty( $input['2fa_enabled'] );
		$allowed_roles                = array_keys( wp_roles()->roles );
		$raw_required                 = array_filter( (array) ( $input['2fa_required_roles'] ?? array() ) );
		$output['2fa_required_roles'] = array_values(
			array_intersect( array_map( 'sanitize_key', $raw_required ), $allowed_roles )
		);

		// Malware scan whitelist — convert raw textarea to array of sanitized paths.
		$raw_whitelist = $input['malware_scan_whitelist_raw'] ?? '';
		$wl_lines      = array_filter( array_map( 'trim', explode( "\n", $raw_whitelist ) ) );
		$output['malware_scan_whitelist'] = array_values( array_map(
			function ( $p ) {
				// Normalize: no leading slash, no ABSPATH prefix, forward slashes.
				$p = wp_normalize_path( $p );
				$p = ltrim( str_replace( wp_normalize_path( ABSPATH ), '', $p ), '/' );
				return sanitize_text_field( $p );
			},
			$wl_lines
		) );

		// Trusted proxy IPs — parse textarea, validate each as IP or CIDR.
		$raw_proxies = $input['trusted_proxy_ips_raw'] ?? '';
		$proxy_lines = array_filter( array_map( 'trim', explode( "\n", $raw_proxies ) ) );
		$output['trusted_proxy_ips_raw'] = implode( "\n", $proxy_lines ); // Keep original for textarea.
		$output['trusted_proxy_ips']     = array();
		foreach ( $proxy_lines as $line ) {
			// Accept plain IP or CIDR notation (e.g. 192.168.1.0/24).
			if ( false !== strpos( $line, '/' ) ) {
				list( $ip_part, $prefix ) = explode( '/', $line, 2 );
				if ( filter_var( trim( $ip_part ), FILTER_VALIDATE_IP ) && ctype_digit( $prefix ) && (int) $prefix <= 128 ) {
					$output['trusted_proxy_ips'][] = sanitize_text_field( $line );
				}
			} elseif ( filter_var( $line, FILTER_VALIDATE_IP ) ) {
				$output['trusted_proxy_ips'][] = sanitize_text_field( $line );
			}
		}

		// WAF custom rules — sanitize each rule's fields.
		$raw_rules              = (array) ( $input['waf_custom_rules'] ?? array() );
		$allowed_severities     = array( 'critical', 'high', 'medium', 'low' );
		$output['waf_custom_rules'] = array();
		foreach ( $raw_rules as $rule ) {
			$id      = sanitize_key( $rule['id'] ?? '' );
			$pattern = sanitize_text_field( wp_unslash( $rule['pattern'] ?? '' ) );
			$desc    = sanitize_text_field( $rule['description'] ?? '' );
			$sev     = in_array( $rule['severity'] ?? '', $allowed_severities, true ) ? $rule['severity'] : 'medium';

			// Validate that the regex actually compiles.
			if ( ! $id || ! $pattern || ! $desc ) {
				continue;
			}
			if ( false === @preg_match( $pattern, '' ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
				continue; // Skip malformed patterns.
			}
			$output['waf_custom_rules'][] = array(
				'id'          => $id,
				'pattern'     => $pattern,
				'description' => $desc,
				'severity'    => $sev,
			);
		}

		// Reschedule the cron if the frequency changed.
		$prev = get_option( 'sentinel_settings', array() );
		if ( ( $prev['scan_frequency'] ?? '' ) !== $output['scan_frequency'] ) {
			$timestamp = wp_next_scheduled( 'sentinel_scheduled_scan' );
			if ( $timestamp ) {
				wp_unschedule_event( $timestamp, 'sentinel_scheduled_scan' );
			}
			wp_schedule_event( time() + MINUTE_IN_SECONDS, $output['scan_frequency'], 'sentinel_scheduled_scan' );
		}

		return $output;
	}

	/**
	 * Add plugin action links.
	 *
	 * @param array $links Existing links.
	 * @return array Modified links.
	 */
	public function add_plugin_links( $links ) {
		$plugin_links = array(
			'<a href="' . esc_url( admin_url( 'admin.php?page=sentinel-security' ) ) . '">' . esc_html__( 'Dashboard', 'wp-sentinel-security' ) . '</a>',
			'<a href="' . esc_url( admin_url( 'admin.php?page=sentinel-settings' ) ) . '">' . esc_html__( 'Settings', 'wp-sentinel-security' ) . '</a>',
		);
		return array_merge( $plugin_links, $links );
	}

	// -------------------------------------------------------------------------
	// Page render methods
	// -------------------------------------------------------------------------

	/**
	 * Render dashboard page.
	 *
	 * @return void
	 */
	public function render_dashboard() {
		$score     = Scoring_Engine::calculate_site_score();
		$last_scan = $this->get_last_scan();
		$alerts    = $this->get_recent_alerts( 10 );
		require SENTINEL_PLUGIN_DIR . 'admin/views/dashboard.php';
	}

	/**
	 * Render scanner page.
	 *
	 * @return void
	 */
	public function render_scanner() {
		$scan_history = Sentinel_DB::get_scan_history( 10 );
		require SENTINEL_PLUGIN_DIR . 'admin/views/scanner.php';
	}

	/**
	 * Render firewall IP manager page.
	 *
	 * @return void
	 */
	public function render_firewall() {
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/firewall/class-ip-manager.php';
		$ip_manager    = new IP_Manager( $this->settings );
		$blocked_ips   = $ip_manager->get_blocked_ips();
		$whitelisted   = $ip_manager->get_whitelisted_ips();
		$firewall_nonce = wp_create_nonce( 'sentinel_firewall_nonce' );
		require SENTINEL_PLUGIN_DIR . 'admin/views/firewall.php';
	}

	/**
	 * Render hardening page.
	 *
	 * @return void
	 */
	public function render_hardening() {
		$hardening_dir = SENTINEL_PLUGIN_DIR . 'includes/modules/hardening/';

		require_once $hardening_dir . 'class-file-hardening.php';
		require_once $hardening_dir . 'class-wp-config-hardening.php';
		require_once $hardening_dir . 'class-user-hardening.php';
		require_once $hardening_dir . 'class-database-hardening.php';
		require_once $hardening_dir . 'class-api-hardening.php';
		require_once $hardening_dir . 'class-hardening-engine.php';

		$engine = new Hardening_Engine( $this->settings );
		$engine->init();

		$checks = $engine->get_all_checks();
		$score  = $engine->get_hardening_score();

		require SENTINEL_PLUGIN_DIR . 'admin/views/hardening.php';
	}

	/**
	 * Render backups page.
	 *
	 * @return void
	 */
	public function render_backups() {
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/backup/class-backup-database.php';
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/backup/class-backup-files.php';
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/backup/class-backup-engine.php';
		$engine       = new Backup_Engine( $this->settings );
		$backups      = $engine->get_backups( 1, 20 );
		$storage_size = $engine->get_backup_storage_size();
		$backup_count = $backups['total'];
		$backups      = $backups['items'];
		require SENTINEL_PLUGIN_DIR . 'admin/views/backups.php';
	}

	/**
	 * Render reports page.
	 *
	 * @return void
	 */
	public function render_reports() {
		$engine       = new Report_Engine( $this->settings );
		$report_data  = $engine->get_reports( 1, 20 );
		$reports      = $report_data['items'];
		$report_count = $report_data['total'];
		require SENTINEL_PLUGIN_DIR . 'admin/views/reports.php';
	}

	/**
	 * Render alerts page.
	 *
	 * @return void
	 */
	public function render_alerts() {
		$settings   = $this->settings;
		$alert_data = Sentinel_DB::get_activity_log( array( 'event_category' => 'alert' ), 1, 20 );
		$alerts     = $alert_data['items'];
		require SENTINEL_PLUGIN_DIR . 'admin/views/alerts.php';
	}

	/**
	 * Render activity log page.
	 *
	 * @return void
	 */
	public function render_activity() {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		$page    = isset( $_GET['paged'] ) ? absint( $_GET['paged'] ) : 1;
		$filters = array();

		if ( ! empty( $_GET['date_from'] ) ) {
			$filters['date_from'] = sanitize_text_field( wp_unslash( $_GET['date_from'] ) );
		}
		if ( ! empty( $_GET['date_to'] ) ) {
			$filters['date_to'] = sanitize_text_field( wp_unslash( $_GET['date_to'] ) );
		}
		if ( ! empty( $_GET['category'] ) ) {
			$filters['event_category'] = sanitize_text_field( wp_unslash( $_GET['category'] ) );
		}
		if ( ! empty( $_GET['severity'] ) ) {
			$filters['severity'] = sanitize_text_field( wp_unslash( $_GET['severity'] ) );
		}
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		$log_data = Sentinel_DB::get_activity_log( $filters, $page, 20 );
		require SENTINEL_PLUGIN_DIR . 'admin/views/activity.php';
	}

	/**
	 * Render intelligence page.
	 *
	 * @return void
	 */
	public function render_intelligence() {
		require SENTINEL_PLUGIN_DIR . 'admin/views/intelligence.php';
	}

	/**
	 * Render settings page.
	 *
	 * @return void
	 */
	public function render_settings() {
		require SENTINEL_PLUGIN_DIR . 'admin/views/settings.php';
	}

	/**
	 * Render setup wizard page.
	 *
	 * @return void
	 */
	public function render_wizard() {
		require SENTINEL_PLUGIN_DIR . 'admin/views/wizard.php';
	}

	// -------------------------------------------------------------------------
	// Helper methods
	// -------------------------------------------------------------------------

	/**
	 * Add a red badge to the WP admin bar when critical or high vulnerabilities are open.
	 *
	 * Mirrors the UX pattern used by Wordfence: the badge appears in the
	 * back-end toolbar and on the front end for logged-in admins.
	 *
	 * @param WP_Admin_Bar $wp_admin_bar Admin bar instance.
	 * @return void
	 */
	public function add_bar_badge( $wp_admin_bar ) {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		// Count open critical + high vulnerabilities, cached for 5 minutes.
		$count = get_transient( 'sentinel_open_critical_count' );

		if ( false === $count ) {
			global $wpdb;
			$table = $wpdb->prefix . 'sentinel_vulnerabilities';
			$count = (int) $wpdb->get_var( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
				"SELECT COUNT(*)
				 FROM `{$table}`
				 WHERE status = 'open'
				   AND severity IN ('critical','high')"
			);
			set_transient( 'sentinel_open_critical_count', $count, 5 * MINUTE_IN_SECONDS );
		}

		if ( $count < 1 ) {
			return;
		}

		$label = sprintf(
			/* translators: %d: Number of open critical/high vulnerabilities */
			_n(
				'Sentinel: %d critical issue',
				'Sentinel: %d critical issues',
				$count,
				'wp-sentinel-security'
			),
			$count
		);

		$wp_admin_bar->add_node( array(
			'id'    => 'sentinel-critical-badge',
			'title' => '<span class="sentinel-bar-badge">' . esc_html( $label ) . '</span>',
			'href'  => admin_url( 'admin.php?page=sentinel-scanner' ),
			'meta'  => array( 'title' => esc_attr( $label ) ),
		) );
	}

	/**
	 * Output minimal inline CSS for the admin bar badge.
	 *
	 * @return void
	 */
	public function enqueue_bar_badge_styles() {
		if ( ! is_admin_bar_showing() || ! current_user_can( 'manage_options' ) ) {
			return;
		}

		if ( ! get_transient( 'sentinel_open_critical_count' ) ) {
			return;
		}

		wp_add_inline_style(
			'admin-bar',
			'
			#wpadminbar #wp-admin-bar-sentinel-critical-badge > .ab-item {
				background: #c62828 !important;
				color: #fff !important;
			}
			#wpadminbar #wp-admin-bar-sentinel-critical-badge > .ab-item:hover {
				background: #b71c1c !important;
			}
			#wpadminbar .sentinel-bar-badge {
				display: inline-block;
				font-weight: 600;
				letter-spacing: 0.01em;
			}
			'
		);
	}

	/**
	 * Get recent alerts from the activity log.
	 *
	 * @param int $limit Number of alerts to retrieve.
	 * @return array
	 */
	private function get_recent_alerts( $limit = 10 ) {
		$log_data = Sentinel_DB::get_activity_log(
			array( 'severity' => 'high' ),
			1,
			$limit
		);
		return $log_data['items'];
	}

	/**
	 * Get the last completed scan.
	 *
	 * @return object|null
	 */
	private function get_last_scan() {
		return Sentinel_DB::get_latest_scan();
	}

	/**
	 * Get list of backups.
	 *
	 * @return array
	 */
	private function get_backups_list() {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$wpdb->prefix}sentinel_backups WHERE status != %s ORDER BY created_at DESC LIMIT 50",
				'deleted'
			)
		);
	}

	/**
	 * AJAX: export activity log as CSV.
	 *
	 * @return void
	 */
	public function ajax_export_activity_log() {
		check_ajax_referer( 'sentinel_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'wp-sentinel-security' ) ), 403 );
		}

		$log_data = Sentinel_DB::get_activity_log( array(), 1, 10000 );
		$items    = $log_data['items'];

		$filename = 'sentinel-activity-log-' . gmdate( 'Y-m-d' ) . '.csv';

		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="' . $filename . '"' );
		header( 'Pragma: no-cache' );
		header( 'Expires: 0' );

		// BOM for Excel compatibility.
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo "\xEF\xBB\xBF";

		$output = fopen( 'php://output', 'w' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen

		fputcsv( $output, array( 'Date', 'User ID', 'Event Type', 'Category', 'Severity', 'IP Address', 'Description' ) );

		foreach ( $items as $item ) {
			fputcsv(
				$output,
				array(
					$item->created_at,
					$item->user_id,
					$item->event_type,
					$item->event_category,
					$item->severity,
					$item->ip_address,
					$item->description,
				)
			);
		}

		fclose( $output ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
		exit;
	}

	/**
	 * AJAX: clear old activity log entries.
	 *
	 * @return void
	 */
	public function ajax_clear_old_logs() {
		check_ajax_referer( 'sentinel_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'wp-sentinel-security' ) ), 403 );
		}

		$retention_days = absint( $this->settings['log_retention_days'] ?? 90 );
		$deleted        = Sentinel_DB::cleanup_old_logs( $retention_days );

		if ( false === $deleted ) {
			wp_send_json_error( array( 'message' => __( 'Failed to clear logs.', 'wp-sentinel-security' ) ) );
		}

		wp_send_json_success(
			array(
				'message' => sprintf(
					/* translators: %d: number of log entries deleted */
					__( '%d log entries deleted.', 'wp-sentinel-security' ),
					(int) $deleted
				),
			)
		);
	}

	/**
	 * AJAX: switch the plugin UI language.
	 *
	 * Saves the chosen locale to the sentinel_language option and reloads
	 * the plugin text domain with the new .mo file (takes effect on next
	 * page load).
	 *
	 * @return void
	 */
	public function ajax_switch_language() {
		check_ajax_referer( 'sentinel_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'wp-sentinel-security' ) ), 403 );
		}

		$allowed_locales = array( '', 'es_ES', 'fr_FR', 'de_DE', 'pt_BR', 'it_IT' );
		$locale          = isset( $_POST['locale'] ) ? sanitize_text_field( wp_unslash( $_POST['locale'] ) ) : '';

		if ( ! in_array( $locale, $allowed_locales, true ) ) {
			wp_send_json_error( array( 'message' => __( 'Invalid language.', 'wp-sentinel-security' ) ) );
		}

		update_option( 'sentinel_language', $locale );

		wp_send_json_success(
			array(
				'message' => __( 'Language updated. The page will reload.', 'wp-sentinel-security' ),
				'locale'  => $locale,
			)
		);
	}

	/**
	 * Admin-post handler: stream a backup file download.
	 *
	 * @return void
	 */

	// -----------------------------------------------------------------------
	// Vulnerability Management AJAX
	// -----------------------------------------------------------------------

	/**
	 * AJAX: mark a single vulnerability as ignored, false_positive, or reopen it.
	 */
	public function ajax_mark_vulnerability() {
		check_ajax_referer( 'sentinel_scan_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'wp-sentinel-security' ) ), 403 );
		}

		$vuln_id = absint( $_POST['vuln_id'] ?? 0 );
		$action  = isset( $_POST['vuln_action'] ) ? sanitize_key( $_POST['vuln_action'] ) : '';

		$allowed_statuses = array( 'open', 'ignored', 'false_positive', 'fixed' );
		if ( ! $vuln_id || ! in_array( $action, $allowed_statuses, true ) ) {
			wp_send_json_error( array( 'message' => __( 'Invalid parameters.', 'wp-sentinel-security' ) ) );
		}

		global $wpdb;

		$resolved_at = in_array( $action, array( 'fixed', 'ignored', 'false_positive' ), true )
			? current_time( 'mysql' )
			: null;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$result = $wpdb->update(
			"{$wpdb->prefix}sentinel_vulnerabilities",
			array(
				'status'      => $action,
				'resolved_at' => $resolved_at,
			),
			array( 'id' => $vuln_id ),
			array( '%s', '%s' ),
			array( '%d' )
		);

		if ( false === $result ) {
			wp_send_json_error( array( 'message' => __( 'Could not update vulnerability.', 'wp-sentinel-security' ) ) );
		}

		wp_send_json_success( array( 'message' => __( 'Status updated.', 'wp-sentinel-security' ), 'new_status' => $action ) );
	}

	/**
	 * AJAX: get full details for a single vulnerability.
	 */
	public function ajax_get_vulnerability() {
		check_ajax_referer( 'sentinel_scan_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'wp-sentinel-security' ) ), 403 );
		}

		$vuln_id = absint( $_POST['vuln_id'] ?? 0 );
		if ( ! $vuln_id ) {
			wp_send_json_error( array( 'message' => __( 'Invalid ID.', 'wp-sentinel-security' ) ) );
		}

		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$vuln = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM {$wpdb->prefix}sentinel_vulnerabilities WHERE id = %d",
				$vuln_id
			)
		);

		if ( ! $vuln ) {
			wp_send_json_error( array( 'message' => __( 'Not found.', 'wp-sentinel-security' ) ) );
		}

		$refs = array();
		if ( ! empty( $vuln->reference_urls ) ) {
			$decoded = json_decode( $vuln->reference_urls, true );
			if ( is_array( $decoded ) ) { $refs = $decoded; }
		}
		$vuln->reference_urls_array = $refs;

		wp_send_json_success( array( 'vulnerability' => $vuln ) );
	}

	/**
	 * AJAX: bulk-mark multiple vulnerabilities.
	 */
	public function ajax_bulk_mark_vulnerability() {
		check_ajax_referer( 'sentinel_scan_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'wp-sentinel-security' ) ), 403 );
		}

		$ids    = isset( $_POST['vuln_ids'] ) ? array_map( 'absint', (array) $_POST['vuln_ids'] ) : array();
		$action = isset( $_POST['vuln_action'] ) ? sanitize_key( $_POST['vuln_action'] ) : '';

		$allowed_statuses = array( 'open', 'ignored', 'false_positive', 'fixed' );
		$ids = array_filter( $ids );
		if ( empty( $ids ) || ! in_array( $action, $allowed_statuses, true ) ) {
			wp_send_json_error( array( 'message' => __( 'Invalid parameters.', 'wp-sentinel-security' ) ) );
		}

		global $wpdb;

		$resolved_at  = in_array( $action, array( 'fixed', 'ignored', 'false_positive' ), true ) ? current_time( 'mysql' ) : null;
		$placeholders = implode( ',', array_fill( 0, count( $ids ), '%d' ) );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$updated = $wpdb->query(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"UPDATE {$wpdb->prefix}sentinel_vulnerabilities SET status = %s, resolved_at = %s WHERE id IN ({$placeholders})",
				array_merge( array( $action, $resolved_at ?? current_time( 'mysql' ) ), $ids )
			)
		);

		wp_send_json_success( array(
			'message' => sprintf( __( '%d vulnerabilities updated.', 'wp-sentinel-security' ), (int) $updated ),
			'updated' => (int) $updated,
		) );
	}

	// ─────────────────────────────────────────────────────────────────────────
	// Firewall IP management AJAX handlers
	// ─────────────────────────────────────────────────────────────────────────

	/**
	 * AJAX: Block an IP address or CIDR range.
	 *
	 * @return void
	 */
	public function ajax_block_ip() {
		check_ajax_referer( 'sentinel_firewall_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'wp-sentinel-security' ) ) );
		}

		$ip     = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
		$reason = isset( $_POST['reason'] ) ? sanitize_text_field( wp_unslash( $_POST['reason'] ) ) : '';
		$expiry = isset( $_POST['expiry'] ) ? absint( $_POST['expiry'] ) : 0;

		if ( empty( $ip ) ) {
			wp_send_json_error( array( 'message' => __( 'IP address is required.', 'wp-sentinel-security' ) ) );
		}

		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/firewall/class-ip-manager.php';
		$manager = new IP_Manager( $this->settings );

		if ( $manager->block_ip( $ip, $reason, $expiry ) ) {
			wp_send_json_success( array( 'message' => __( 'IP blocked successfully.', 'wp-sentinel-security' ) ) );
		} else {
			wp_send_json_error( array( 'message' => __( 'Invalid IP address or CIDR notation.', 'wp-sentinel-security' ) ) );
		}
	}

	/**
	 * AJAX: Unblock an IP address or CIDR range.
	 *
	 * @return void
	 */
	public function ajax_unblock_ip() {
		check_ajax_referer( 'sentinel_firewall_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'wp-sentinel-security' ) ) );
		}

		$ip = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';

		if ( empty( $ip ) ) {
			wp_send_json_error( array( 'message' => __( 'IP address is required.', 'wp-sentinel-security' ) ) );
		}

		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/firewall/class-ip-manager.php';
		$manager = new IP_Manager( $this->settings );

		if ( $manager->unblock_ip( $ip ) ) {
			wp_send_json_success( array( 'message' => __( 'IP unblocked successfully.', 'wp-sentinel-security' ) ) );
		} else {
			wp_send_json_error( array( 'message' => __( 'IP was not in the blocked list.', 'wp-sentinel-security' ) ) );
		}
	}

	/**
	 * AJAX: Add an IP address or CIDR range to the whitelist.
	 *
	 * @return void
	 */
	public function ajax_whitelist_ip() {
		check_ajax_referer( 'sentinel_firewall_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'wp-sentinel-security' ) ) );
		}

		$ip    = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
		$label = isset( $_POST['label'] ) ? sanitize_text_field( wp_unslash( $_POST['label'] ) ) : '';

		if ( empty( $ip ) ) {
			wp_send_json_error( array( 'message' => __( 'IP address is required.', 'wp-sentinel-security' ) ) );
		}

		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/firewall/class-ip-manager.php';
		$manager = new IP_Manager( $this->settings );

		if ( $manager->whitelist_ip( $ip, $label ) ) {
			wp_send_json_success( array( 'message' => __( 'IP whitelisted successfully.', 'wp-sentinel-security' ) ) );
		} else {
			wp_send_json_error( array( 'message' => __( 'Invalid IP address or CIDR notation.', 'wp-sentinel-security' ) ) );
		}
	}

	/**
	 * AJAX: Remove an IP address or CIDR range from the whitelist.
	 *
	 * @return void
	 */
	public function ajax_unwhitelist_ip() {
		check_ajax_referer( 'sentinel_firewall_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'wp-sentinel-security' ) ) );
		}

		$ip = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';

		if ( empty( $ip ) ) {
			wp_send_json_error( array( 'message' => __( 'IP address is required.', 'wp-sentinel-security' ) ) );
		}

		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/firewall/class-ip-manager.php';
		$manager = new IP_Manager( $this->settings );

		if ( $manager->remove_whitelist( $ip ) ) {
			wp_send_json_success( array( 'message' => __( 'IP removed from whitelist.', 'wp-sentinel-security' ) ) );
		} else {
			wp_send_json_error( array( 'message' => __( 'IP was not in the whitelist.', 'wp-sentinel-security' ) ) );
		}
	}

	// ─────────────────────────────────────────────────────────────────────────
	// Scheduled scan: trigger immediately
	// ─────────────────────────────────────────────────────────────────────────

	/**
	 * AJAX: reschedule the next sentinel_scheduled_scan event to fire in
	 * 10 seconds so the admin can verify cron is working without waiting.
	 *
	 * @return void
	 */
	public function ajax_run_cron_now() {
		check_ajax_referer( 'sentinel_run_cron_now', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'wp-sentinel-security' ) ) );
		}

		// Clear existing schedule then re-add 10 s from now.
		$existing = wp_next_scheduled( 'sentinel_scheduled_scan' );
		if ( $existing ) {
			wp_unschedule_event( $existing, 'sentinel_scheduled_scan' );
		}

		wp_schedule_single_event( time() + 10, 'sentinel_scheduled_scan' );

		wp_send_json_success( array(
			'message' => __( 'Scan queued — it will run within the next minute (subject to WP-Cron frequency).', 'wp-sentinel-security' ),
		) );
	}

	// ─────────────────────────────────────────────────────────────────────────
	// WAF custom rule test
	// ─────────────────────────────────────────────────────────────────────────

	/**
	 * AJAX: Validate a custom WAF regex and optionally test it against a sample input.
	 *
	 * Expected POST params:
	 *   nonce   – wp_nonce for 'sentinel_test_waf_rule'
	 *   pattern – PHP-compatible regex string (including delimiters)
	 *   input   – (optional) string to match against
	 *
	 * Returns JSON { matched: bool } on success or { message: string } on error.
	 *
	 * @return void
	 */
	public function ajax_test_waf_rule() {
		check_ajax_referer( 'sentinel_test_waf_rule', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'wp-sentinel-security' ) ) );
		}

		$pattern = sanitize_text_field( wp_unslash( $_POST['pattern'] ?? '' ) );
		$input   = wp_unslash( $_POST['input'] ?? '' );

		if ( empty( $pattern ) ) {
			wp_send_json_error( array( 'message' => __( 'No pattern provided.', 'wp-sentinel-security' ) ) );
		}

		// Validate: attempt a safe regex compilation.
		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		$result = @preg_match( $pattern, '' );
		if ( false === $result ) {
			$error = preg_last_error_msg();
			wp_send_json_error( array(
				'message' => sprintf(
					/* translators: %s: regex error message */
					__( 'Invalid regex: %s', 'wp-sentinel-security' ),
					$error
				),
			) );
		}

		// Test against sample input if provided.
		$matched = false;
		if ( '' !== $input ) {
			// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			$matched = (bool) @preg_match( $pattern, $input );
		}

		wp_send_json_success( array( 'matched' => $matched ) );
	}

	// ─────────────────────────────────────────────────────────────────────────
	// Vulnerability CSV export
	// ─────────────────────────────────────────────────────────────────────────

	/**
	 * AJAX: stream the vulnerability table as a CSV download.
	 *
	 * Accepts optional GET/POST params:
	 *   severity  – one of critical|high|medium|low|info|all (default: all)
	 *   status    – one of open|fixed|ignored|false_positive|all (default: open)
	 *   scan_id   – integer; filters to a specific scan (default: all scans)
	 *
	 * @return void  Streams CSV and exits.
	 */
	public function ajax_export_vulnerabilities() {
		check_ajax_referer( 'sentinel_scan_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'wp-sentinel-security' ) ) );
		}

		global $wpdb;

		$table    = $wpdb->prefix . 'sentinel_vulnerabilities';
		$scans    = $wpdb->prefix . 'sentinel_scans';

		// ── Build query dynamically from filters ────────────────────────────
		$where  = array( '1=1' );
		$params = array();

		$severity_filter = sanitize_text_field( wp_unslash( $_REQUEST['severity'] ?? 'all' ) );
		$valid_severities = array( 'critical', 'high', 'medium', 'low', 'info' );
		if ( in_array( $severity_filter, $valid_severities, true ) ) {
			$where[]  = 'v.severity = %s';
			$params[] = $severity_filter;
		}

		$status_filter = sanitize_text_field( wp_unslash( $_REQUEST['status'] ?? 'open' ) );
		$valid_statuses = array( 'open', 'fixed', 'ignored', 'false_positive' );
		if ( in_array( $status_filter, $valid_statuses, true ) ) {
			$where[]  = 'v.status = %s';
			$params[] = $status_filter;
		}

		$scan_id = absint( $_REQUEST['scan_id'] ?? 0 );
		if ( $scan_id > 0 ) {
			$where[]  = 'v.scan_id = %d';
			$params[] = $scan_id;
		}

		$where_sql = implode( ' AND ', $where );

		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery
		$query = "SELECT
			v.id,
			v.scan_id,
			s.scan_type,
			v.component_type,
			v.component_name,
			v.component_version,
			v.vulnerability_id,
			v.title,
			v.severity,
			v.cvss_score,
			v.status,
			v.detected_at,
			v.resolved_at,
			v.recommendation,
			v.description
		FROM `{$table}` v
		LEFT JOIN `{$scans}` s ON s.id = v.scan_id
		WHERE {$where_sql}
		ORDER BY
			FIELD(v.severity,'critical','high','medium','low','info'),
			v.detected_at DESC";

		$rows = empty( $params )
			? $wpdb->get_results( $query, ARRAY_A )
			: $wpdb->get_results( $wpdb->prepare( $query, $params ), ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		// phpcs:enable

		if ( is_null( $rows ) ) {
			wp_send_json_error( array( 'message' => __( 'Database error while exporting.', 'wp-sentinel-security' ) ) );
		}

		// ── Stream CSV ──────────────────────────────────────────────────────
		$filename = 'sentinel-vulnerabilities-' . gmdate( 'Y-m-d' );
		if ( 'all' !== $severity_filter ) {
			$filename .= '-' . $severity_filter;
		}
		$filename .= '.csv';

		// Prevent any output buffering from interfering.
		while ( ob_get_level() ) {
			ob_end_clean();
		}

		header( 'Content-Type: text/csv; charset=UTF-8' );
		header( 'Content-Disposition: attachment; filename="' . $filename . '"' );
		header( 'Pragma: no-cache' );
		header( 'Expires: 0' );

		// UTF-8 BOM so Excel opens without encoding issues.
		echo "\xEF\xBB\xBF"; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped

		$out = fopen( 'php://output', 'w' );

		// Header row.
		fputcsv( $out, array(
			'ID', 'Scan ID', 'Scan Type',
			'Component Type', 'Component Name', 'Version',
			'CVE / Vuln ID', 'Title', 'Severity', 'CVSS Score',
			'Status', 'Detected At', 'Resolved At',
			'Recommendation', 'Description',
		) );

		foreach ( $rows as $row ) {
			fputcsv( $out, array(
				$row['id'],
				$row['scan_id'],
				$row['scan_type'] ?? '',
				$row['component_type'],
				$row['component_name'],
				$row['component_version'],
				$row['vulnerability_id'],
				$row['title'],
				$row['severity'],
				$row['cvss_score'],
				$row['status'],
				$row['detected_at'],
				$row['resolved_at'] ?? '',
				$row['recommendation'],
				wp_strip_all_tags( $row['description'] ),
			) );
		}

		fclose( $out ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
		exit;
	}

	public function handle_download_backup() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Insufficient permissions.', 'wp-sentinel-security' ), 403 );
		}

		$backup_id = isset( $_GET['backup_id'] ) ? absint( $_GET['backup_id'] ) : 0;

		if ( ! $backup_id ) {
			wp_die( esc_html__( 'Invalid backup ID.', 'wp-sentinel-security' ) );
		}

		$nonce_key = 'sentinel_download_backup_' . $backup_id;
		if ( ! isset( $_GET['_wpnonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ) ), $nonce_key ) ) {
			wp_die( esc_html__( 'Security check failed.', 'wp-sentinel-security' ) );
		}

		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$backup = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM {$wpdb->prefix}sentinel_backups WHERE id = %d AND status = %s",
				$backup_id,
				'completed'
			)
		);

		if ( ! $backup || empty( $backup->file_path ) || ! file_exists( $backup->file_path ) ) {
			wp_die( esc_html__( 'Backup file not found.', 'wp-sentinel-security' ) );
		}

		$extension = strtolower( pathinfo( $backup->file_path, PATHINFO_EXTENSION ) );
		$mime      = ( 'zip' === $extension ) ? 'application/zip' : 'application/octet-stream';

		header( 'Content-Type: ' . $mime );
		header( 'Content-Disposition: attachment; filename="' . sanitize_file_name( basename( $backup->file_path ) ) . '"' );
		header( 'Content-Length: ' . filesize( $backup->file_path ) );
		header( 'Pragma: no-cache' );
		header( 'Expires: 0' );

		readfile( $backup->file_path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_readfile
		exit;
	}

	// ─────────────────────────────────────────────────────────────────────────
	// New feature render methods (v2.8)
	// ─────────────────────────────────────────────────────────────────────────

	/**
	 * Render: Security Headers page.
	 *
	 * @return void
	 */
	public function render_headers() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Insufficient permissions.', 'wp-sentinel-security' ) );
		}
		require SENTINEL_PLUGIN_DIR . 'admin/views/headers.php';
	}

	/**
	 * Render: Last Logins page.
	 *
	 * @return void
	 */
	public function render_lastlogins() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Insufficient permissions.', 'wp-sentinel-security' ) );
		}
		require SENTINEL_PLUGIN_DIR . 'admin/views/lastlogins.php';
	}

	/**
	 * Render: Security Recommendations page.
	 *
	 * @return void
	 */
	public function render_recommendations() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Insufficient permissions.', 'wp-sentinel-security' ) );
		}
		require SENTINEL_PLUGIN_DIR . 'admin/views/recommendations.php';
	}

	/**
	 * Emit HTTP security headers on every request.
	 * Hooked to 'send_headers' (runs before any output).
	 *
	 * @return void
	 */
	public function emit_security_headers() {
		if ( ! class_exists( 'Sentinel_Security_Headers' ) ) {
			require_once SENTINEL_PLUGIN_DIR . 'includes/modules/hardening/class-security-headers.php';
		}
		Sentinel_Security_Headers::send();
	}

	/**
	 * Register Last Logins tracking hooks.
	 * Hooked to 'init' so the login/logout actions are always registered.
	 *
	 * @return void
	 */
	public function register_last_logins_hooks() {
		if ( ! class_exists( 'Sentinel_Last_Logins' ) ) {
			require_once SENTINEL_PLUGIN_DIR . 'includes/modules/activity/class-last-logins.php';
		}
		Sentinel_Last_Logins::register_hooks();
	}
}
