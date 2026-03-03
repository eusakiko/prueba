<?php
/**
 * Plugin deactivator class.
 *
 * Handles deactivation tasks such as clearing scheduled cron events.
 *
 * @package WP_Sentinel_Security
 * @since   1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Sentinel_Deactivator
 */
class Sentinel_Deactivator {

	/**
	 * Run deactivation tasks.
	 *
	 * @return void
	 */
	public static function deactivate() {
		$cron_hooks = array(
			'sentinel_scheduled_scan',
			'sentinel_cleanup_logs',
			'sentinel_vulnerability_feed_update',
			'sentinel_backup_cleanup',
			'sentinel_scheduled_report',         // BUG FIX: was missing, caused orphan cron after deactivation.
			'sentinel_run_async_scan',       // BUG FIX: async one-time events.
			'sentinel_lockdown_auto_disable', // BUG FIX: lockdown expiry events.
		);

		foreach ( $cron_hooks as $hook ) {
			wp_clear_scheduled_hook( $hook );
		}

		if ( class_exists( 'Sentinel_Cache' ) ) {
			Sentinel_Cache::flush_all();
		}
	}
}
