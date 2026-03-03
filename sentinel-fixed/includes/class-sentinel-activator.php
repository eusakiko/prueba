<?php
/**
 * Plugin activator class.
 *
 * Handles all activation tasks: database creation, option defaults,
 * backup directory setup, and cron scheduling.
 *
 * @package WP_Sentinel_Security
 * @since   1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Sentinel_Activator
 */
class Sentinel_Activator {

	/**
	 * Run all activation routines.
	 *
	 * @return void
	 */
	public static function activate() {
		self::create_tables();
		self::set_default_options();
		self::create_backup_directory();
		self::schedule_cron_events();
		update_option( 'sentinel_needs_initial_scan', true );
		update_option( 'sentinel_activated_at', current_time( 'mysql' ) );
		update_option( 'sentinel_db_version', SENTINEL_DB_VERSION );
	}

	/**
	 * Run upgrade routines for existing installs.
	 *
	 * Called on every admin_init when the stored DB version is behind
	 * SENTINEL_DB_VERSION, so upgrades apply without re-activating.
	 *
	 * @return void
	 */
	public static function maybe_upgrade() {
		$installed = get_option( 'sentinel_db_version', '1.0.0' );

		if ( version_compare( $installed, SENTINEL_DB_VERSION, '>=' ) ) {
			return;
		}

		if ( version_compare( $installed, '2.0.0', '<' ) ) {
			self::upgrade_200();
		}

		update_option( 'sentinel_db_version', SENTINEL_DB_VERSION );
	}

	/**
	 * DB upgrade to 2.0.0: widen component_type ENUM to include ssl,
	 * database, header and network — values that were silently truncated
	 * to empty string by MySQL in v1.x, breaking severity filters.
	 *
	 * @return void
	 */
	private static function upgrade_200() {
		global $wpdb;
		$table = $wpdb->prefix . 'sentinel_vulnerabilities';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->query(
			"ALTER TABLE `{$table}`
			MODIFY COLUMN `component_type`
			ENUM('core','plugin','theme','file','config','user','ssl','database','header','network')
			NOT NULL DEFAULT 'plugin'"
		);
	}

	/**
	 * Create plugin database tables using dbDelta.
	 *
	 * @return void
	 */
	private static function create_tables() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$charset_collate = $wpdb->get_charset_collate();
		$prefix          = $wpdb->prefix;

		// Vulnerabilities table.
		$sql = "CREATE TABLE {$prefix}sentinel_vulnerabilities (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			scan_id bigint(20) unsigned NOT NULL DEFAULT 0,
			component_type enum('core','plugin','theme','file','config','user','ssl','database','header','network') NOT NULL DEFAULT 'plugin',
			component_name varchar(255) NOT NULL DEFAULT '',
			component_version varchar(50) NOT NULL DEFAULT '',
			vulnerability_id varchar(100) NOT NULL DEFAULT '',
			title varchar(500) NOT NULL DEFAULT '',
			description longtext NOT NULL,
			severity enum('critical','high','medium','low','info') NOT NULL DEFAULT 'medium',
			cvss_score decimal(4,1) NOT NULL DEFAULT '0.0',
			cvss_vector varchar(100) NOT NULL DEFAULT '',
			status enum('open','fixed','ignored','false_positive') NOT NULL DEFAULT 'open',
			recommendation text NOT NULL,
			reference_urls longtext,
			detected_at datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
			resolved_at datetime DEFAULT NULL,
			PRIMARY KEY (id),
			KEY scan_id (scan_id),
			KEY severity (severity),
			KEY status (status),
			KEY component_type (component_type)
		) $charset_collate;";
		dbDelta( $sql );

		// Scans table.
		$sql = "CREATE TABLE {$prefix}sentinel_scans (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			scan_type enum('full','quick','core','plugins','themes','files','config','user_audit','malware','integrity','database','compliance','ssl','headers') NOT NULL DEFAULT 'full',
			status enum('pending','running','completed','failed','cancelled') NOT NULL DEFAULT 'pending',
			started_at datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
			completed_at datetime DEFAULT NULL,
			total_checks int(11) NOT NULL DEFAULT 0,
			vulnerabilities_found int(11) NOT NULL DEFAULT 0,
			risk_score decimal(5,2) NOT NULL DEFAULT '100.00',
			summary longtext,
			triggered_by varchar(100) NOT NULL DEFAULT 'manual',
			PRIMARY KEY (id),
			KEY status (status),
			KEY scan_type (scan_type),
			KEY started_at (started_at)
		) $charset_collate;";
		dbDelta( $sql );

		// Backups table.
		$sql = "CREATE TABLE {$prefix}sentinel_backups (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			backup_type enum('full','database','files','plugins','themes') NOT NULL DEFAULT 'database',
			file_path varchar(500) NOT NULL DEFAULT '',
			file_size bigint(20) unsigned NOT NULL DEFAULT 0,
			storage_location enum('local','remote','s3','ftp') NOT NULL DEFAULT 'local',
			status enum('pending','in_progress','completed','failed','deleted') NOT NULL DEFAULT 'pending',
			checksum varchar(64) NOT NULL DEFAULT '',
			notes text NOT NULL,
			created_at datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
			expires_at datetime DEFAULT NULL,
			PRIMARY KEY (id),
			KEY status (status),
			KEY created_at (created_at)
		) $charset_collate;";
		dbDelta( $sql );

		// Activity log table.
		$sql = "CREATE TABLE {$prefix}sentinel_activity_log (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			user_id bigint(20) unsigned NOT NULL DEFAULT 0,
			event_type varchar(100) NOT NULL DEFAULT '',
			event_category varchar(100) NOT NULL DEFAULT '',
			severity enum('critical','high','medium','low','info') NOT NULL DEFAULT 'info',
			description text NOT NULL,
			ip_address varchar(45) NOT NULL DEFAULT '',
			user_agent text NOT NULL,
			object_type varchar(100) NOT NULL DEFAULT '',
			object_id varchar(100) NOT NULL DEFAULT '',
			metadata longtext,
			created_at datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
			PRIMARY KEY (id),
			KEY user_id (user_id),
			KEY event_type (event_type),
			KEY severity (severity),
			KEY created_at (created_at)
		) $charset_collate;";
		dbDelta( $sql );

		// Hardening status table.
		$sql = "CREATE TABLE {$prefix}sentinel_hardening_status (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			check_id varchar(100) NOT NULL DEFAULT '',
			check_name varchar(255) NOT NULL DEFAULT '',
			category varchar(100) NOT NULL DEFAULT '',
			status enum('pass','fail','warning','skipped') NOT NULL DEFAULT 'fail',
			applied_at datetime DEFAULT NULL,
			details longtext,
			PRIMARY KEY (id),
			UNIQUE KEY check_id (check_id)
		) $charset_collate;";
		dbDelta( $sql );

		// File integrity table.
		$sql = "CREATE TABLE {$prefix}sentinel_file_integrity (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			file_path varchar(1000) NOT NULL DEFAULT '',
			file_hash varchar(64) NOT NULL DEFAULT '',
			expected_hash varchar(64) NOT NULL DEFAULT '',
			file_size bigint(20) unsigned NOT NULL DEFAULT 0,
			file_permissions varchar(10) NOT NULL DEFAULT '',
			status enum('clean','modified','new','deleted','suspicious') NOT NULL DEFAULT 'clean',
			last_checked datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
			PRIMARY KEY (id),
			KEY status (status),
			KEY last_checked (last_checked)
		) $charset_collate;";
		dbDelta( $sql );

		// Reports table.
		$sql = "CREATE TABLE {$prefix}sentinel_reports (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			report_type enum('vulnerability','compliance','executive','full') NOT NULL DEFAULT 'full',
			title varchar(500) NOT NULL DEFAULT '',
			format enum('pdf','html','csv','json') NOT NULL DEFAULT 'html',
			file_path varchar(500) NOT NULL DEFAULT '',
			scan_ids longtext,
			branding_config longtext,
			generated_by bigint(20) unsigned NOT NULL DEFAULT 0,
			created_at datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
			PRIMARY KEY (id),
			KEY report_type (report_type),
			KEY created_at (created_at)
		) $charset_collate;";
		dbDelta( $sql );

		// Last Logins table.
		if ( ! class_exists( 'Sentinel_Last_Logins' ) ) {
			require_once SENTINEL_PLUGIN_DIR . 'includes/modules/activity/class-last-logins.php';
		}
		Sentinel_Last_Logins::create_table();
	}
	/**
	 * Set default plugin options on first activation.
	 *
	 * @return void
	 */
	private static function set_default_options() {
		$defaults = array(
			'scan_frequency'       => 'daily',
			'backup_before_action' => true,
			'alert_email'          => get_option( 'admin_email' ),
			'alert_channels'       => array( 'email' ),
			'scoring_method'       => 'cvss_v3',
			'log_retention_days'   => 90,
			'async_scanning'       => false, // Off by default: WP-Cron is unreliable in Docker/local without external traffic.
			'wpscan_api_key'       => '',
			'slack_webhook'        => '',
			'telegram_bot_token'   => '',
			'telegram_chat_id'     => '',
			'company_name'         => get_option( 'blogname' ),
			'company_logo'         => '',
		);

		if ( ! get_option( 'sentinel_settings' ) ) {
			add_option( 'sentinel_settings', $defaults );
		}
	}

	/**
	 * Create backup directory with protective files.
	 *
	 * @return void
	 */
	private static function create_backup_directory() {
		$backup_dir = WP_CONTENT_DIR . '/uploads/sentinel-backups/';

		if ( ! is_dir( $backup_dir ) ) {
			wp_mkdir_p( $backup_dir );
		}

		// Create .htaccess to deny direct access.
		$htaccess = $backup_dir . '.htaccess';
		if ( ! file_exists( $htaccess ) ) {
			file_put_contents( // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
				$htaccess,
				"Order Deny,Allow\nDeny from all\n"
			);
		}

		// Create index.php to prevent directory listing.
		$index = $backup_dir . 'index.php';
		if ( ! file_exists( $index ) ) {
			file_put_contents( // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
				$index,
				"<?php\n// Silence is golden.\n"
			);
		}
	}

	/**
	 * Schedule plugin cron events.
	 *
	 * @return void
	 */
	private static function schedule_cron_events() {
		if ( ! wp_next_scheduled( 'sentinel_scheduled_scan' ) ) {
			wp_schedule_event( time(), 'daily', 'sentinel_scheduled_scan' );
		}

		if ( ! wp_next_scheduled( 'sentinel_cleanup_logs' ) ) {
			wp_schedule_event( time(), 'weekly', 'sentinel_cleanup_logs' );
		}

		if ( ! wp_next_scheduled( 'sentinel_vulnerability_feed_update' ) ) {
			wp_schedule_event( time(), 'twicedaily', 'sentinel_vulnerability_feed_update' );
		}

		if ( ! wp_next_scheduled( 'sentinel_backup_cleanup' ) ) {
			wp_schedule_event( time(), 'daily', 'sentinel_backup_cleanup' );
		}
	}
}
