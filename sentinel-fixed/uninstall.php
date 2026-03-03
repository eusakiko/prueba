<?php
/**
 * Uninstall WP Sentinel Security
 *
 * Fired when the plugin is uninstalled. Removes all plugin data.
 *
 * @package WP_Sentinel_Security
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

global $wpdb;

// Drop all plugin tables.
$tables = array(
	'sentinel_vulnerabilities',
	'sentinel_scans',
	'sentinel_backups',
	'sentinel_activity_log',
	'sentinel_hardening_status',
	'sentinel_file_integrity',
	'sentinel_reports',
);

foreach ( $tables as $table ) {
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
	$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}{$table}" );
}

// Delete plugin options.
$options = array(
	'sentinel_settings',
	'sentinel_db_version',
	'sentinel_needs_initial_scan',
	'sentinel_activated_at',
);

foreach ( $options as $option ) {
	delete_option( $option );
	delete_site_option( $option );
}

// Clean transients.
$wpdb->query(
	$wpdb->prepare(
		"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s",
		$wpdb->esc_like( '_transient_sentinel_' ) . '%',
		$wpdb->esc_like( '_transient_timeout_sentinel_' ) . '%'
	)
);

if ( is_multisite() ) {
	$wpdb->query(
		$wpdb->prepare(
			"DELETE FROM {$wpdb->sitemeta} WHERE meta_key LIKE %s OR meta_key LIKE %s",
			$wpdb->esc_like( '_site_transient_sentinel_' ) . '%',
			$wpdb->esc_like( '_site_transient_timeout_sentinel_' ) . '%'
		)
	);
}

// Remove scheduled cron events.
$cron_hooks = array(
	'sentinel_scheduled_scan',
	'sentinel_cleanup_logs',
	'sentinel_vulnerability_feed_update',
	'sentinel_backup_cleanup',
);

foreach ( $cron_hooks as $hook ) {
	$timestamp = wp_next_scheduled( $hook );
	if ( $timestamp ) {
		wp_unschedule_event( $timestamp, $hook );
	}
	wp_clear_scheduled_hook( $hook );
}

// Recursively delete backup directory.
$backup_dir = WP_CONTENT_DIR . '/uploads/sentinel-backups/';

// Canonicalize path and verify it is within the expected uploads directory
// to prevent accidental traversal via symlinks or unexpected path components.
$real_backup_dir    = realpath( $backup_dir );
$real_content_dir   = realpath( WP_CONTENT_DIR );

if (
	$real_backup_dir &&
	$real_content_dir &&
	0 === strpos( $real_backup_dir, $real_content_dir . DIRECTORY_SEPARATOR ) &&
	is_dir( $real_backup_dir ) &&
	is_writable( $real_backup_dir )
) {
	sentinel_uninstall_delete_directory( $real_backup_dir );
}

/**
 * Recursively delete a directory and its contents.
 *
 * Symlinks are unlinked rather than recursed into to prevent traversal
 * outside the intended directory tree.
 *
 * @param string $dir Canonicalized directory path to delete.
 */
function sentinel_uninstall_delete_directory( $dir ) {
	if ( ! is_dir( $dir ) ) {
		return;
	}

	$items = scandir( $dir );
	foreach ( $items as $item ) {
		if ( '.' === $item || '..' === $item ) {
			continue;
		}
		$path = $dir . DIRECTORY_SEPARATOR . $item;
		if ( is_link( $path ) ) {
			// Unlink symlinks without following them.
			unlink( $path );
		} elseif ( is_dir( $path ) ) {
			sentinel_uninstall_delete_directory( $path );
		} elseif ( is_file( $path ) ) {
			unlink( $path );
		}
	}
	rmdir( $dir );
}
