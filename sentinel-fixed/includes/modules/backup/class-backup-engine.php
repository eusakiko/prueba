<?php
/**
 * Backup engine — orchestrates all backup and restore operations.
 *
 * Coordinates the database and file-system backup sub-classes, manages
 * the sentinel_backups database table, logs to the activity log, and
 * exposes AJAX handlers for the admin UI.
 *
 * @package WP_Sentinel_Security
 * @since   2.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Backup_Engine
 *
 * Central orchestrator for Phase 4 backup functionality.
 */
class Backup_Engine {

	/**
	 * Plugin settings.
	 *
	 * @var array
	 */
	private $settings;

	/**
	 * Database backup handler instance.
	 *
	 * @var Backup_Database
	 */
	private $db_handler;

	/**
	 * File backup handler instance.
	 *
	 * @var Backup_Files
	 */
	private $files_handler;

	/**
	 * Absolute path to the sentinel backup storage directory.
	 *
	 * @var string
	 */
	private $backup_dir;

	/**
	 * Constructor.
	 *
	 * @param array $settings Plugin settings array.
	 */
	public function __construct( $settings = array() ) {
		$this->settings   = $settings;
		$this->backup_dir = WP_CONTENT_DIR . '/uploads/sentinel-backups/';
	}

	/**
	 * Initialise the engine: load sub-classes and register AJAX hooks.
	 *
	 * @return void
	 */
	public function init() {
		$backup_dir = SENTINEL_PLUGIN_DIR . 'includes/modules/backup/';

		require_once $backup_dir . 'class-backup-database.php';
		require_once $backup_dir . 'class-backup-files.php';

		$this->db_handler    = new Backup_Database();
		$this->files_handler = new Backup_Files();

		add_action( 'wp_ajax_sentinel_create_backup',       array( $this, 'ajax_create_backup' ) );
		add_action( 'wp_ajax_sentinel_restore_backup',      array( $this, 'ajax_restore_backup' ) );
		add_action( 'wp_ajax_sentinel_delete_backup',       array( $this, 'ajax_delete_backup' ) );
		add_action( 'wp_ajax_sentinel_get_backup_progress', array( $this, 'ajax_get_backup_progress' ) );
	}

	// -----------------------------------------------------------------------
	// AJAX handlers
	// -----------------------------------------------------------------------

	/**
	 * AJAX: create a new backup.
	 *
	 * Expected POST fields: nonce, type (full|database|files).
	 *
	 * @return void
	 */
	public function ajax_create_backup() {
		check_ajax_referer( 'sentinel_backup_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'wp-sentinel-security' ) ), 403 );
		}

		$type = isset( $_POST['type'] ) ? sanitize_text_field( wp_unslash( $_POST['type'] ) ) : 'full';

		if ( ! in_array( $type, array( 'full', 'database', 'files' ), true ) ) {
			wp_send_json_error( array( 'message' => __( 'Invalid backup type.', 'wp-sentinel-security' ) ) );
		}

		$this->ensure_handlers();

		$result = $this->create_backup( $type );

		if ( is_wp_error( $result ) ) {
			wp_send_json_error( array( 'message' => $result->get_error_message() ) );
		}

		wp_send_json_success(
			array(
				'backup_id' => $result,
				'message'   => __( 'Backup created successfully.', 'wp-sentinel-security' ),
			)
		);
	}

	/**
	 * AJAX: restore a backup.
	 *
	 * Expected POST fields: nonce, backup_id.
	 *
	 * @return void
	 */
	public function ajax_restore_backup() {
		check_ajax_referer( 'sentinel_backup_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'wp-sentinel-security' ) ), 403 );
		}

		$backup_id = absint( $_POST['backup_id'] ?? 0 );
		if ( ! $backup_id ) {
			wp_send_json_error( array( 'message' => __( 'Invalid backup ID.', 'wp-sentinel-security' ) ) );
		}

		$this->ensure_handlers();

		$result = $this->restore_backup( $backup_id );

		if ( is_wp_error( $result ) ) {
			wp_send_json_error( array( 'message' => $result->get_error_message() ) );
		}

		wp_send_json_success( array( 'message' => __( 'Backup restored successfully.', 'wp-sentinel-security' ) ) );
	}

	/**
	 * AJAX: delete a backup.
	 *
	 * Expected POST fields: nonce, backup_id.
	 *
	 * @return void
	 */
	public function ajax_delete_backup() {
		check_ajax_referer( 'sentinel_backup_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'wp-sentinel-security' ) ), 403 );
		}

		$backup_id = absint( $_POST['backup_id'] ?? 0 );
		if ( ! $backup_id ) {
			wp_send_json_error( array( 'message' => __( 'Invalid backup ID.', 'wp-sentinel-security' ) ) );
		}

		$result = $this->delete_backup( $backup_id );

		if ( is_wp_error( $result ) ) {
			wp_send_json_error( array( 'message' => $result->get_error_message() ) );
		}

		wp_send_json_success( array( 'message' => __( 'Backup deleted successfully.', 'wp-sentinel-security' ) ) );
	}

	/**
	 * AJAX: get the current backup creation progress.
	 *
	 * Returns the percentage stored in the `sentinel_backup_progress` transient.
	 *
	 * @return void
	 */
	public function ajax_get_backup_progress() {
		check_ajax_referer( 'sentinel_backup_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'wp-sentinel-security' ) ), 403 );
		}

		$progress = (int) get_transient( 'sentinel_backup_progress' );
		wp_send_json_success( array( 'progress' => $progress ) );
	}

	// -----------------------------------------------------------------------
	// Core engine methods
	// -----------------------------------------------------------------------

	/**
	 * Create a new backup.
	 *
	 * Supported types:
	 * - 'database' — SQL dump only.
	 * - 'files'    — ZIP archive of WP_CONTENT_DIR.
	 * - 'full'     — SQL dump + files ZIP, both stored individually.
	 *
	 * @param string $type Backup type: 'full', 'database', or 'files'.
	 * @return int|WP_Error Backup row ID on success, WP_Error on failure.
	 */
	public function create_backup( $type = 'full' ) {
		global $wpdb;

		$this->ensure_handlers();
		$this->ensure_backup_dir();

		$timestamp = gmdate( 'Y-m-d_H-i-s' );
		$result    = null;

		if ( 'database' === $type || 'full' === $type ) {
			$db_file = $this->backup_dir . "sentinel-db-{$timestamp}.sql";
			$result  = $this->db_handler->export( $db_file );
			if ( is_wp_error( $result ) ) {
				return $result;
			}
		}

		if ( 'files' === $type || 'full' === $type ) {
			$zip_file = $this->backup_dir . "sentinel-files-{$timestamp}.zip";
			$result   = $this->files_handler->create_archive( $zip_file );
			if ( is_wp_error( $result ) ) {
				return $result;
			}
		}

		// For 'full', we record the files ZIP as the primary artefact;
		// the SQL dump lives alongside it on disk.
		if ( 'full' === $type ) {
			$primary_file = $zip_file;
		} elseif ( 'database' === $type ) {
			$primary_file = $db_file;
		} else {
			$primary_file = $zip_file;
		}

		if ( ! file_exists( $primary_file ) ) {
			return new WP_Error(
				'backup_file_missing_after_create',
				__( 'Backup file was not created successfully.', 'wp-sentinel-security' )
			);
		}

		$file_size = filesize( $primary_file );
		$checksum  = hash_file( 'sha256', $primary_file );
		$expires   = gmdate( 'Y-m-d H:i:s', time() + ( 30 * DAY_IN_SECONDS ) );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$inserted = $wpdb->insert(
			"{$wpdb->prefix}sentinel_backups",
			array(
				'backup_type'      => $type,
				'file_path'        => $primary_file,
				'file_size'        => $file_size,
				'storage_location' => 'local',
				'status'           => 'completed',
				'checksum'         => $checksum,
				'notes'            => '',
				'created_at'       => current_time( 'mysql' ),
				'expires_at'       => $expires,
			),
			array( '%s', '%s', '%d', '%s', '%s', '%s', '%s', '%s', '%s' )
		);

		if ( false === $inserted ) {
			return new WP_Error(
				'backup_db_insert_failed',
				__( 'Failed to record backup in the database.', 'wp-sentinel-security' )
			);
		}

		$backup_id = $wpdb->insert_id;

		$this->log_activity(
			'backup_created',
			'backup',
			'info',
			sprintf(
				/* translators: 1: backup type, 2: backup ID */
				__( 'Backup created — type: %1$s, ID: %2$d', 'wp-sentinel-security' ),
				$type,
				$backup_id
			),
			'backup',
			(string) $backup_id
		);

		return $backup_id;
	}

	/**
	 * Restore a backup by its database ID.
	 *
	 * Only backups with status 'completed' can be restored.
	 * The method verifies the file checksum before proceeding.
	 *
	 * @param int $backup_id Backup row ID.
	 * @return true|WP_Error True on success, WP_Error on failure.
	 */
	public function restore_backup( $backup_id ) {
		global $wpdb;

		$this->ensure_handlers();

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$backup = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM {$wpdb->prefix}sentinel_backups WHERE id = %d",
				$backup_id
			)
		);

		if ( ! $backup ) {
			return new WP_Error(
				'backup_not_found',
				__( 'Backup record not found.', 'wp-sentinel-security' )
			);
		}

		if ( 'completed' !== $backup->status ) {
			return new WP_Error(
				'backup_not_completed',
				__( 'Only completed backups can be restored.', 'wp-sentinel-security' )
			);
		}

		if ( ! file_exists( $backup->file_path ) ) {
			return new WP_Error(
				'backup_file_missing',
				__( 'Backup file not found on disk.', 'wp-sentinel-security' )
			);
		}

		// Verify checksum integrity.
		$actual_checksum = hash_file( 'sha256', $backup->file_path );
		if ( ! hash_equals( $backup->checksum, $actual_checksum ) ) {
			return new WP_Error(
				'backup_checksum_mismatch',
				__( 'Backup file checksum verification failed. The file may be corrupted.', 'wp-sentinel-security' )
			);
		}

		$extension = strtolower( pathinfo( $backup->file_path, PATHINFO_EXTENSION ) );

		if ( 'sql' === $extension ) {
			$result = $this->db_handler->import( $backup->file_path );
		} elseif ( 'zip' === $extension ) {
			$result = $this->files_handler->extract_archive( $backup->file_path );
		} else {
			return new WP_Error(
				'backup_unknown_type',
				__( 'Unknown backup file type; cannot restore.', 'wp-sentinel-security' )
			);
		}

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		$this->log_activity(
			'backup_restored',
			'backup',
			'high',
			sprintf(
				/* translators: %d: backup ID */
				__( 'Backup restored — ID: %d', 'wp-sentinel-security' ),
				$backup_id
			),
			'backup',
			(string) $backup_id
		);

		return true;
	}

	/**
	 * Delete a backup: verify checksum, remove physical file, update DB record.
	 *
	 * The database row is kept but its status is set to 'deleted' so that
	 * the audit trail is preserved.
	 *
	 * @param int $backup_id Backup row ID.
	 * @return true|WP_Error True on success, WP_Error on failure.
	 */
	public function delete_backup( $backup_id ) {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$backup = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM {$wpdb->prefix}sentinel_backups WHERE id = %d",
				$backup_id
			)
		);

		if ( ! $backup ) {
			return new WP_Error(
				'backup_not_found',
				__( 'Backup record not found.', 'wp-sentinel-security' )
			);
		}

		if ( 'deleted' === $backup->status ) {
			return new WP_Error(
				'backup_already_deleted',
				__( 'Backup has already been deleted.', 'wp-sentinel-security' )
			);
		}

		// Verify checksum before deleting (only when the file still exists).
		if ( file_exists( $backup->file_path ) && ! empty( $backup->checksum ) ) {
			$actual_checksum = hash_file( 'sha256', $backup->file_path );
			if ( ! hash_equals( $backup->checksum, $actual_checksum ) ) {
				return new WP_Error(
					'backup_checksum_mismatch',
					__( 'Backup file checksum verification failed. Deletion aborted to protect data integrity.', 'wp-sentinel-security' )
				);
			}

			// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
			if ( ! unlink( $backup->file_path ) ) {
				return new WP_Error(
					'backup_delete_failed',
					__( 'Could not remove the backup file from disk.', 'wp-sentinel-security' )
				);
			}
		}

		// For full backups there may also be a companion SQL file on disk.
		// We compute and log its SHA-256 before deletion so the admin has an
		// audit record (the SQL file has no stored checksum in the DB schema).
		if ( 'full' === $backup->backup_type ) {
			$sql_companion = str_replace( '-files-', '-db-', str_replace( '.zip', '.sql', $backup->file_path ) );
			if ( file_exists( $sql_companion ) ) {
				$sql_checksum = hash_file( 'sha256', $sql_companion );
				if ( false !== $sql_checksum ) {
					$this->log_activity(
						'backup_sql_companion_deleted',
						'backup',
						'info',
						array( 'file' => basename( $sql_companion ), 'sha256' => $sql_checksum )
					);
				}
				// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
				unlink( $sql_companion );
			}
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->update(
			"{$wpdb->prefix}sentinel_backups",
			array( 'status' => 'deleted' ),
			array( 'id' => $backup_id ),
			array( '%s' ),
			array( '%d' )
		);

		$this->log_activity(
			'backup_deleted',
			'backup',
			'medium',
			sprintf(
				/* translators: %d: backup ID */
				__( 'Backup deleted — ID: %d', 'wp-sentinel-security' ),
				$backup_id
			),
			'backup',
			(string) $backup_id
		);

		return true;
	}

	/**
	 * Retrieve a paginated list of backups (excluding deleted ones).
	 *
	 * @param int $page     Page number (1-based).
	 * @param int $per_page Number of items per page.
	 * @return array {
	 *     @type array $items  Array of stdClass backup objects.
	 *     @type int   $total  Total number of backups.
	 *     @type int   $pages  Total number of pages.
	 * }
	 */
	public function get_backups( $page = 1, $per_page = 20 ) {
		global $wpdb;

		$page     = max( 1, (int) $page );
		$per_page = max( 1, (int) $per_page );
		$offset   = ( $page - 1 ) * $per_page;

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
				$per_page,
				$offset
			)
		);

		return array(
			'items' => $items ?: array(),
			'total' => $total,
			'pages' => $total > 0 ? (int) ceil( $total / $per_page ) : 1,
		);
	}

	/**
	 * Remove backups older than the specified number of days.
	 *
	 * Iterates through expired records and calls delete_backup() on each
	 * so that files are removed and the audit trail is maintained.
	 *
	 * @param int $max_age_days Maximum age of backups to keep (default: 30).
	 * @return int Number of backups deleted.
	 */
	public function cleanup_old_backups( $max_age_days = 30 ) {
		global $wpdb;

		$cutoff = gmdate( 'Y-m-d H:i:s', time() - ( (int) $max_age_days * DAY_IN_SECONDS ) );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$old_backups = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT id FROM {$wpdb->prefix}sentinel_backups WHERE status = %s AND created_at < %s",
				'completed',
				$cutoff
			)
		);

		$deleted = 0;
		foreach ( $old_backups as $row ) {
			$result = $this->delete_backup( (int) $row->id );
			if ( ! is_wp_error( $result ) ) {
				$deleted++;
			}
		}

		return $deleted;
	}

	/**
	 * Calculate the total storage consumed by all non-deleted backups.
	 *
	 * @return int Total size in bytes.
	 */
	public function get_backup_storage_size() {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$size = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COALESCE(SUM(file_size), 0) FROM {$wpdb->prefix}sentinel_backups WHERE status != %s",
				'deleted'
			)
		);

		return (int) $size;
	}

	// -----------------------------------------------------------------------
	// Private helpers
	// -----------------------------------------------------------------------

	/**
	 * Ensure sub-class handlers are instantiated.
	 *
	 * Called lazily so that the engine is usable even when init() has not
	 * been invoked (e.g., from the admin render method).
	 *
	 * @return void
	 */
	private function ensure_handlers() {
		if ( ! isset( $this->db_handler ) ) {
			$backup_dir = SENTINEL_PLUGIN_DIR . 'includes/modules/backup/';
			require_once $backup_dir . 'class-backup-database.php';
			require_once $backup_dir . 'class-backup-files.php';
			$this->db_handler    = new Backup_Database();
			$this->files_handler = new Backup_Files();
		}
	}

	/**
	 * Ensure the backup storage directory exists and is protected.
	 *
	 * @return void
	 */
	private function ensure_backup_dir() {
		if ( ! is_dir( $this->backup_dir ) ) {
			wp_mkdir_p( $this->backup_dir );
		}

		$htaccess = $this->backup_dir . '.htaccess';
		if ( ! file_exists( $htaccess ) ) {
			file_put_contents( // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
				$htaccess,
				"Order Deny,Allow\nDeny from all\n"
			);
		}

		$index = $this->backup_dir . 'index.php';
		if ( ! file_exists( $index ) ) {
			file_put_contents( // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
				$index,
				"<?php\n// Silence is golden.\n"
			);
		}
	}

	/**
	 * Insert a record into the sentinel_activity_log table.
	 *
	 * @param string $event_type     Short machine-readable event type.
	 * @param string $event_category Category (e.g., 'backup').
	 * @param string $severity       One of: critical, high, medium, low, info.
	 * @param string $description    Human-readable description.
	 * @param string $object_type    Type of the affected object.
	 * @param string $object_id      ID of the affected object.
	 * @return void
	 */
	private function log_activity( $event_type, $event_category, $severity, $description, $object_type = '', $object_id = '' ) {
		global $wpdb;

		$user_id    = get_current_user_id();
		$ip_address = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		$user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$wpdb->insert(
			"{$wpdb->prefix}sentinel_activity_log",
			array(
				'user_id'        => $user_id,
				'event_type'     => $event_type,
				'event_category' => $event_category,
				'severity'       => $severity,
				'description'    => $description,
				'ip_address'     => $ip_address,
				'user_agent'     => $user_agent,
				'object_type'    => $object_type,
				'object_id'      => $object_id,
				'metadata'       => '',
				'created_at'     => current_time( 'mysql' ),
			),
			array( '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s' )
		);
	}
}
