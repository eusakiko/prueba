<?php
/**
 * Cron management class.
 *
 * Registers custom cron schedules and connects action hooks to callbacks.
 *
 * @package WP_Sentinel_Security
 * @since   1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Sentinel_Cron
 */
class Sentinel_Cron {

	/**
	 * Register cron schedules and action hooks.
	 *
	 * @return void
	 */
	public static function register() {
		// Add custom intervals.
		add_filter( 'cron_schedules', array( __CLASS__, 'add_cron_intervals' ) );

		// Connect cron hooks to callbacks.
		add_action( 'sentinel_scheduled_scan',            array( __CLASS__, 'run_scheduled_scan' ) );
		add_action( 'sentinel_cleanup_logs',              array( __CLASS__, 'run_log_cleanup' ) );
		add_action( 'sentinel_vulnerability_feed_update', array( __CLASS__, 'run_feed_update' ) );
		add_action( 'sentinel_backup_cleanup',            array( __CLASS__, 'run_backup_cleanup' ) );
		add_action( 'sentinel_scheduled_report',          array( __CLASS__, 'run_scheduled_report' ) );

		// BUG FIX: Register the async scan hook that Scanner_Engine schedules
		// via wp_schedule_single_event(). Without this registration the cron
		// event fires but nothing happens.
		add_action( 'sentinel_run_async_scan', array( __CLASS__, 'run_async_scan' ), 10, 2 );
	}

	/**
	 * Add custom cron intervals (weekly, monthly).
	 *
	 * @param array $schedules Existing schedules.
	 * @return array Modified schedules.
	 */
	public static function add_cron_intervals( $schedules ) {
		if ( ! isset( $schedules['weekly'] ) ) {
			$schedules['weekly'] = array(
				'interval' => WEEK_IN_SECONDS,
				'display'  => __( 'Once Weekly', 'wp-sentinel-security' ),
			);
		}

		if ( ! isset( $schedules['monthly'] ) ) {
			$schedules['monthly'] = array(
				'interval' => MONTH_IN_SECONDS,
				'display'  => __( 'Once Monthly', 'wp-sentinel-security' ),
			);
		}

		return $schedules;
	}

	/**
	 * Run the scheduled security scan using the type configured in Settings.
	 *
	 * Defaults to 'quick' if no type has been saved. The 'full' option is
	 * supported but should be reserved for low-traffic windows given its
	 * 5–10 minute runtime.
	 *
	 * @return void
	 */
	public static function run_scheduled_scan() {
		if ( ! class_exists( 'Scanner_Engine' ) ) {
			return;
		}

		$settings  = get_option( 'sentinel_settings', array() );
		$scan_type = isset( $settings['scheduled_scan_type'] ) && 'full' === $settings['scheduled_scan_type']
			? 'full'
			: 'quick';

		$engine = new Scanner_Engine( $settings );
		$engine->init();
		$engine->run_scan( $scan_type, 'cron' );
	}

	/**
	 * Execute an async scan triggered by wp_schedule_single_event().
	 *
	 * @param int    $scan_id   Existing scan row ID.
	 * @param string $scan_type Scan type key.
	 * @return void
	 */
	public static function run_async_scan( $scan_id, $scan_type ) {
		$scanner_dir = defined( 'SENTINEL_PLUGIN_DIR' ) ? SENTINEL_PLUGIN_DIR . 'includes/modules/scanner/' : '';
		if ( ! $scanner_dir || ! is_dir( $scanner_dir ) ) {
			return;
		}

		$files = array(
			'class-core-integrity.php',
			'class-plugin-vulnerability.php',
			'class-theme-vulnerability.php',
			'class-config-analyzer.php',
			'class-permission-checker.php',
			'class-file-monitor.php',
			'class-malware-detector.php',
			'class-user-audit.php',
			'class-database-scanner.php',
			'class-compliance-checker.php',
			'class-ssl-scanner.php',
			'class-header-analyzer.php',
		);
		foreach ( $files as $file ) {
			$path = $scanner_dir . $file;
			if ( file_exists( $path ) ) {
				require_once $path;
			}
		}

		if ( ! class_exists( 'Scanner_Engine' ) ) {
			return;
		}

		$engine = new Scanner_Engine( get_option( 'sentinel_settings', array() ) );
		$engine->run_scan( sanitize_text_field( $scan_type ), 'async', absint( $scan_id ) );
	}

	/**
	 * Run log cleanup.
	 *
	 * @return void
	 */
	public static function run_log_cleanup() {
		$settings = get_option( 'sentinel_settings', array() );
		$days     = isset( $settings['log_retention_days'] ) ? absint( $settings['log_retention_days'] ) : 90;
		Sentinel_DB::cleanup_old_logs( $days );
	}

	/**
	 * Update the vulnerability feed cache.
	 *
	 * @return void
	 */
	public static function run_feed_update() {
		Sentinel_Cache::flush_all();
	}

	/**
	 * Clean up expired backups.
	 *
	 * @return void
	 */
	public static function run_backup_cleanup() {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$expired = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$wpdb->prefix}sentinel_backups WHERE expires_at < %s AND status = %s",
				current_time( 'mysql' ),
				'completed'
			)
		);

		foreach ( $expired as $backup ) {
			if ( file_exists( $backup->file_path ) ) {
				unlink( $backup->file_path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
			}

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$wpdb->update(
				"{$wpdb->prefix}sentinel_backups",
				array( 'status' => 'deleted' ),
				array( 'id' => $backup->id ),
				array( '%s' ),
				array( '%d' )
			);
		}
	}

	/**
	 * Send scheduled report via email.
	 *
	 * @return void
	 */
	public static function run_scheduled_report() {
		$settings = get_option( 'sentinel_settings', array() );
		if ( empty( $settings['scheduled_report_email'] ) ) {
			return;
		}
		if ( class_exists( 'Report_Engine' ) ) {
			$engine = new Report_Engine( $settings );
			$engine->init();
			$report_id = $engine->generate_report( 'executive', 'html' );
			if ( ! is_wp_error( $report_id ) && class_exists( 'Alert_Email' ) ) {
				$mailer  = new Alert_Email( $settings );
				$mailer->send(
					__( 'WP Sentinel Security — Scheduled Security Report', 'wp-sentinel-security' ),
					__( 'Your scheduled security report is ready. Please log in to your WordPress dashboard to view it.', 'wp-sentinel-security' ),
					array( 'severity' => 'info' )
				);
			}
		}
	}
}
