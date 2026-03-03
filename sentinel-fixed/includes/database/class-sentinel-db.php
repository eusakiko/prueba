<?php
/**
 * Database helper class.
 *
 * Static helper methods for common database queries with prepared statements.
 *
 * @package WP_Sentinel_Security
 * @since   1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Sentinel_DB
 */
class Sentinel_DB {

	/**
	 * Get open vulnerabilities with optional filters.
	 *
	 * @param array $filters Optional filters: severity, component_type, status.
	 * @return array
	 */
	public static function get_open_vulnerabilities( $filters = array() ) {
		global $wpdb;

		$where  = array( '1=1' );
		$params = array();

		if ( ! empty( $filters['severity'] ) ) {
			$where[]  = 'severity = %s';
			$params[] = sanitize_text_field( $filters['severity'] );
		}

		if ( ! empty( $filters['component_type'] ) ) {
			$where[]  = 'component_type = %s';
			$params[] = sanitize_text_field( $filters['component_type'] );
		}

		if ( ! empty( $filters['status'] ) ) {
			$where[]  = 'status = %s';
			$params[] = sanitize_text_field( $filters['status'] );
		} else {
			$where[]  = 'status = %s';
			$params[] = 'open';
		}

		$where_clause = implode( ' AND ', $where );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		return $wpdb->get_results(
			// phpcs:ignore WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT * FROM {$wpdb->prefix}sentinel_vulnerabilities WHERE {$where_clause} ORDER BY cvss_score DESC, detected_at DESC",
				...$params
			)
		);
	}

	/**
	 * Get the latest completed scan.
	 *
	 * @return object|null
	 */
	public static function get_latest_scan() {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		return $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM {$wpdb->prefix}sentinel_scans WHERE status = %s ORDER BY completed_at DESC LIMIT 1",
				'completed'
			)
		);
	}

	/**
	 * Get scan history.
	 *
	 * @param int $limit  Number of scans to return.
	 * @param int $offset Number of scans to skip (for pagination).
	 * @return array
	 */
	public static function get_scan_history( $limit = 20, $offset = 0 ) {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$wpdb->prefix}sentinel_scans ORDER BY started_at DESC LIMIT %d OFFSET %d",
				absint( $limit ),
				absint( $offset )
			)
		);
	}

	/**
	 * Get activity log with pagination.
	 *
	 * @param array $filters  Optional filters: severity, event_type, event_category, user_id, date_from, date_to.
	 * @param int   $page     Page number (1-based).
	 * @param int   $per_page Items per page.
	 * @return array {items: array, total: int, pages: int}
	 */
	public static function get_activity_log( $filters = array(), $page = 1, $per_page = 20 ) {
		global $wpdb;

		$where  = array( '1=1' );
		$params = array();

		if ( ! empty( $filters['severity'] ) ) {
			$where[]  = 'severity = %s';
			$params[] = sanitize_text_field( $filters['severity'] );
		}

		if ( ! empty( $filters['event_type'] ) ) {
			$where[]  = 'event_type = %s';
			$params[] = sanitize_text_field( $filters['event_type'] );
		}

		if ( ! empty( $filters['event_category'] ) ) {
			$where[]  = 'event_category = %s';
			$params[] = sanitize_text_field( $filters['event_category'] );
		}

		if ( ! empty( $filters['user_id'] ) ) {
			$where[]  = 'user_id = %d';
			$params[] = absint( $filters['user_id'] );
		}

		if ( ! empty( $filters['date_from'] ) ) {
			$date_from = sanitize_text_field( $filters['date_from'] );
			if ( preg_match( '/^\d{4}-\d{2}-\d{2}$/', $date_from ) ) {
				$where[]  = 'created_at >= %s';
				$params[] = $date_from . ' 00:00:00';
			}
		}

		if ( ! empty( $filters['date_to'] ) ) {
			$date_to = sanitize_text_field( $filters['date_to'] );
			if ( preg_match( '/^\d{4}-\d{2}-\d{2}$/', $date_to ) ) {
				$where[]  = 'created_at <= %s';
				$params[] = $date_to . ' 23:59:59';
			}
		}

		$where_clause = implode( ' AND ', $where );
		$offset       = ( max( 1, (int) $page ) - 1 ) * absint( $per_page );

		$count_params = $params;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$total = (int) $wpdb->get_var(
			// phpcs:ignore WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->prefix}sentinel_activity_log WHERE {$where_clause}",
				...$count_params
			)
		);

		$query_params = array_merge( $params, array( absint( $per_page ), $offset ) );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$items = $wpdb->get_results(
			// phpcs:ignore WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->prepare(
				"SELECT * FROM {$wpdb->prefix}sentinel_activity_log WHERE {$where_clause} ORDER BY created_at DESC LIMIT %d OFFSET %d",
				...$query_params
			)
		);

		return array(
			'items' => $items,
			'total' => $total,
			'pages' => (int) ceil( $total / max( 1, $per_page ) ),
		);
	}

	/**
	 * Get hardening status for all checks.
	 *
	 * @return array
	 */
	public static function get_hardening_status() {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		return $wpdb->get_results(
			"SELECT * FROM {$wpdb->prefix}sentinel_hardening_status ORDER BY category, check_name" // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		);
	}

	/**
	 * Delete activity log entries older than a given number of days.
	 *
	 * @param int $days Retention period in days.
	 * @return int|false Number of rows deleted or false on error.
	 */
	public static function cleanup_old_logs( $days ) {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		return $wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->prefix}sentinel_activity_log WHERE created_at < DATE_SUB(NOW(), INTERVAL %d DAY)",
				absint( $days )
			)
		);
	}

	/**
	 * Log an activity event.
	 *
	 * @param array $data Event data.
	 * @return int|false Insert ID or false on error.
	 */
	public static function log_activity( $data ) {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$result = $wpdb->insert(
			"{$wpdb->prefix}sentinel_activity_log",
			array(
				'user_id'        => absint( $data['user_id'] ?? get_current_user_id() ),
				'event_type'     => sanitize_text_field( $data['event_type'] ?? '' ),
				'event_category' => sanitize_text_field( $data['event_category'] ?? '' ),
				'severity'       => sanitize_text_field( $data['severity'] ?? 'info' ),
				'description'    => sanitize_text_field( $data['description'] ?? '' ),
				'ip_address'     => sanitize_text_field( $data['ip_address'] ?? '' ),
				'user_agent'     => sanitize_text_field( $data['user_agent'] ?? '' ),
				'object_type'    => sanitize_text_field( $data['object_type'] ?? '' ),
				'object_id'      => sanitize_text_field( $data['object_id'] ?? '' ),
				'metadata'       => wp_json_encode( $data['metadata'] ?? array() ),
				'created_at'     => current_time( 'mysql' ),
			),
			array( '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s' )
		);
		return $result ? $wpdb->insert_id : false;
	}

	/**
	 * Get reports with pagination.
	 *
	 * @param int $page     Page number.
	 * @param int $per_page Results per page.
	 * @return array
	 */
	public static function get_reports( $page = 1, $per_page = 20 ) {
		global $wpdb;
		$offset = ( max( 1, (int) $page ) - 1 ) * absint( $per_page );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$total = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}sentinel_reports" ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$items = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$wpdb->prefix}sentinel_reports ORDER BY created_at DESC LIMIT %d OFFSET %d",
				absint( $per_page ),
				$offset
			)
		);
		return array(
			'items' => $items,
			'total' => $total,
			'pages' => (int) ceil( $total / max( 1, $per_page ) ),
		);
	}

	/**
	 * Save a report record.
	 *
	 * @param array $data Report data.
	 * @return int|false Insert ID or false on error.
	 */
	public static function save_report( $data ) {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$result = $wpdb->insert(
			"{$wpdb->prefix}sentinel_reports",
			array(
				'report_type'     => sanitize_text_field( $data['report_type'] ?? 'full' ),
				'title'           => sanitize_text_field( $data['title'] ?? '' ),
				'format'          => sanitize_text_field( $data['format'] ?? 'html' ),
				'file_path'       => sanitize_text_field( $data['file_path'] ?? '' ),
				'scan_ids'        => wp_json_encode( $data['scan_ids'] ?? array() ),
				'branding_config' => wp_json_encode( $data['branding_config'] ?? array() ),
				'generated_by'    => absint( $data['generated_by'] ?? get_current_user_id() ),
				'created_at'      => current_time( 'mysql' ),
			),
			array( '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s' )
		);
		return $result ? $wpdb->insert_id : false;
	}

	/**
	 * Delete a report record.
	 *
	 * @param int $id Report ID.
	 * @return int|false Rows deleted or false on error.
	 */
	public static function delete_report( $id ) {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		return $wpdb->delete(
			"{$wpdb->prefix}sentinel_reports",
			array( 'id' => absint( $id ) ),
			array( '%d' )
		);
	}

	/**
	 * Get vulnerability summary by severity.
	 *
	 * @return array Associative array of severity => count.
	 */
	public static function get_vulnerability_summary() {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT severity, COUNT(*) as count FROM {$wpdb->prefix}sentinel_vulnerabilities WHERE status = %s GROUP BY severity",
				'open'
			)
		);
		$summary = array( 'critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0 );
		foreach ( $rows as $row ) {
			$summary[ $row->severity ] = (int) $row->count;
		}
		return $summary;
	}

	/**
	 * Get backup list with pagination.
	 *
	 * @param int $page     Page number.
	 * @param int $per_page Results per page.
	 * @return array
	 */
	public static function get_backup_list( $page = 1, $per_page = 20 ) {
		global $wpdb;
		$offset = ( max( 1, (int) $page ) - 1 ) * absint( $per_page );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$total = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->prefix}sentinel_backups WHERE status != %s",
				'deleted'
			)
		);
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$items = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$wpdb->prefix}sentinel_backups WHERE status != %s ORDER BY created_at DESC LIMIT %d OFFSET %d",
				'deleted',
				absint( $per_page ),
				$offset
			)
		);
		return array(
			'items' => $items,
			'total' => $total,
			'pages' => (int) ceil( $total / max( 1, $per_page ) ),
		);
	}

	/**
	 * Save a backup record.
	 *
	 * @param array $data Backup data.
	 * @return int|false Insert ID or false on error.
	 */
	public static function save_backup( $data ) {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$result = $wpdb->insert(
			"{$wpdb->prefix}sentinel_backups",
			array(
				'backup_type'      => sanitize_text_field( $data['backup_type'] ?? 'full' ),
				'file_path'        => sanitize_text_field( $data['file_path'] ?? '' ),
				'file_size'        => absint( $data['file_size'] ?? 0 ),
				'storage_location' => 'local',
				'status'           => sanitize_text_field( $data['status'] ?? 'completed' ),
				'checksum'         => sanitize_text_field( $data['checksum'] ?? '' ),
				'notes'            => sanitize_text_field( $data['notes'] ?? '' ),
				'created_at'       => current_time( 'mysql' ),
				'expires_at'       => $data['expires_at'] ?? null,
			),
			array( '%s', '%s', '%d', '%s', '%s', '%s', '%s', '%s', '%s' )
		);
		return $result ? $wpdb->insert_id : false;
	}

	/**
	 * Delete a backup record (mark as deleted).
	 *
	 * @param int $id Backup ID.
	 * @return int|false Rows updated or false on error.
	 */
	public static function delete_backup_record( $id ) {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		return $wpdb->update(
			"{$wpdb->prefix}sentinel_backups",
			array( 'status' => 'deleted' ),
			array( 'id' => absint( $id ) ),
			array( '%s' ),
			array( '%d' )
		);
	}
}
