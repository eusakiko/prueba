<?php
/**
 * Core plugin class.
 *
 * Manages plugin initialization, settings, dependencies, modules, and hooks.
 *
 * @package WP_Sentinel_Security
 * @since   1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Sentinel_Core
 *
 * Singleton core orchestrator for WP Sentinel Security.
 */
class Sentinel_Core {

	/**
	 * Single instance of the class.
	 *
	 * @var Sentinel_Core
	 */
	private static $instance = null;

	/**
	 * Loaded modules.
	 *
	 * @var array
	 */
	private $modules = array();

	/**
	 * Plugin settings.
	 *
	 * @var array
	 */
	private $settings = array();

	/**
	 * Get singleton instance.
	 *
	 * @return Sentinel_Core
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Private constructor — use get_instance().
	 */
	private function __construct() {}

	/**
	 * Initialize the plugin.
	 *
	 * @return void
	 */
	public function init() {
		$this->load_settings();
		$this->load_dependencies();
		$this->register_modules();
		$this->init_modules();
		$this->register_hooks();
	}

	/**
	 * Load plugin settings with defaults.
	 *
	 * @return void
	 */
	private function load_settings() {
		$defaults = array(
			'scan_frequency'       => 'daily',
			'backup_before_action' => true,
			'alert_email'          => get_option( 'admin_email' ),
			'alert_channels'       => array( 'email' ),
			'scoring_method'       => 'cvss_v3',
			'log_retention_days'   => 90,
			'async_scanning'       => false, // Off by default: WP-Cron is unreliable in Docker/local without external traffic.
			'trusted_proxy_ips'    => array(), // Parsed IP/CIDR list (used by Rate_Limiter & Firewall_Engine).
			'waf_custom_rules'     => array(), // Admin-defined WAF regex rules.
		);

		$saved          = get_option( 'sentinel_settings', array() );
		$this->settings = wp_parse_args( $saved, $defaults );
	}

	/**
	 * Load required files.
	 *
	 * @return void
	 */
	private function load_dependencies() {
		// Utilities.
		require_once SENTINEL_PLUGIN_DIR . 'includes/utils/class-sentinel-helper.php';
		require_once SENTINEL_PLUGIN_DIR . 'includes/utils/class-sentinel-cron.php';
		require_once SENTINEL_PLUGIN_DIR . 'includes/utils/class-sentinel-cache.php';
		require_once SENTINEL_PLUGIN_DIR . 'includes/utils/class-scoring-engine.php';

		// Database.
		require_once SENTINEL_PLUGIN_DIR . 'includes/database/class-sentinel-db.php';

		// API.
		require_once SENTINEL_PLUGIN_DIR . 'includes/api/class-vulnerability-feed.php';
		require_once SENTINEL_PLUGIN_DIR . 'includes/api/class-sentinel-rest-api.php';

		// Admin.
		if ( is_admin() ) {
			require_once SENTINEL_PLUGIN_DIR . 'admin/class-sentinel-admin.php';
		}
	}

	/**
	 * Register scanner module.
	 *
	 * @return void
	 */
	private function register_modules() {
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/scanner/class-scanner-engine.php';
		$this->modules['scanner'] = new Scanner_Engine( $this->settings );

		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/intelligence/class-intelligence-engine.php';
		$this->modules['intelligence'] = new Intelligence_Engine( $this->settings );

		// Hardening module.
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/hardening/class-file-hardening.php';
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/hardening/class-wp-config-hardening.php';
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/hardening/class-user-hardening.php';
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/hardening/class-database-hardening.php';
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/hardening/class-api-hardening.php';
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/hardening/class-hardening-engine.php';
		$this->modules['hardening'] = new Hardening_Engine( $this->settings );

		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/backup/class-backup-database.php';
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/backup/class-backup-files.php';
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/backup/class-backup-engine.php';
		$this->modules['backup'] = new Backup_Engine( $this->settings );

		// Reports module.
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/reports/class-report-json-renderer.php';
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/reports/class-report-csv-renderer.php';
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/reports/class-report-html-renderer.php';
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/reports/class-report-engine.php';
		$this->modules['reports'] = new Report_Engine( $this->settings );

		// Alert module.
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/alerts/class-alert-email.php';
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/alerts/class-alert-slack.php';
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/alerts/class-alert-telegram.php';
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/alerts/class-alert-discord.php';
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/alerts/class-alert-webhook.php';
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/alerts/class-alert-engine.php';
		$this->modules['alerts'] = new Alert_Engine( $this->settings );

		// Activity logger.
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/activity/class-activity-logger.php';
		$this->modules['activity'] = new Activity_Logger();

		// Firewall (WAF) module.
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/firewall/class-ip-manager.php';
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/firewall/class-firewall-engine.php';
		$this->modules['firewall'] = new Firewall_Engine( $this->settings );

		// Two-factor authentication module.
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/auth/class-two-factor-auth.php';
		$this->modules['two_factor'] = new Two_Factor_Auth( $this->settings );

		// Firewall extensions: lockdown mode.
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/firewall/class-lockdown.php';
		$this->modules['lockdown'] = new Sentinel_Lockdown( $this->settings );

		// Intelligence extensions.
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/intelligence/class-ip-reputation.php';
		$this->modules['ip_reputation'] = new IP_Reputation( $this->settings, $this->modules['firewall']->get_ip_manager() );

		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/intelligence/class-vulnerability-feed-aggregator.php';
		$this->modules['vuln_feed'] = new Vulnerability_Feed_Aggregator( $this->settings );

		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/intelligence/class-blacklist-monitor.php';
		$this->modules['blacklist_monitor'] = new Blacklist_Monitor( $this->settings );
	}

	/**
	 * Initialize all registered modules.
	 *
	 * @return void
	 */
	private function init_modules() {
		foreach ( $this->modules as $module ) {
			if ( method_exists( $module, 'init' ) ) {
				$module->init();
			}
		}
	}

	/**
	 * Register core plugin hooks.
	 *
	 * @return void
	 */
	private function register_hooks() {
		// Cron.
		Sentinel_Cron::register();

		// REST API.
		add_action( 'rest_api_init', array( 'Sentinel_Rest_Api', 'register_routes' ) );

		// DB upgrades for existing installs (runs once per version bump).
		add_action( 'admin_init', array( 'Sentinel_Activator', 'maybe_upgrade' ) );

		// Bust the admin-bar badge cache whenever a scan finishes.
		add_action( 'sentinel_scan_complete', array( $this, 'bust_critical_count_cache' ) );

		// Admin.
		if ( is_admin() ) {
			$admin = new Sentinel_Admin( $this->settings );
			$admin->register();
		}

		// WP-CLI commands.
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			require_once SENTINEL_PLUGIN_DIR . 'includes/cli/class-sentinel-cli.php';
		}
	}

	/**
	 * Get a setting value.
	 *
	 * @param string $key     Setting key.
	 * @param mixed  $default Default value.
	 * @return mixed
	 */
	public function get_setting( $key, $default = null ) {
		return isset( $this->settings[ $key ] ) ? $this->settings[ $key ] : $default;
	}

	/**
	 * Get all settings.
	 *
	 * @return array
	 */
	public function get_settings() {
		return $this->settings;
	}

	/**
	 * Delete the admin-bar badge transient so it refreshes on the next page load.
	 *
	 * Hooked to sentinel_scan_complete so the count is always fresh after
	 * a scan finishes rather than waiting up to 5 minutes for the cache to expire.
	 *
	 * @return void
	 */
	public function bust_critical_count_cache() {
		delete_transient( 'sentinel_open_critical_count' );
	}
}
