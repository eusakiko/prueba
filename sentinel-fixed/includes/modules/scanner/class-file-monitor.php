<?php
/**
 * File Monitor / File Integrity Scanner.
 *
 * Creates and compares SHA-256 file hashes to detect unauthorized changes.
 *
 * @package WP_Sentinel_Security
 * @since   1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class File_Monitor
 */
class File_Monitor {

	/**
	 * Plugin settings.
	 *
	 * @var array
	 */
	private $settings;

	/**
	 * Maximum number of files to scan.
	 *
	 * @var int
	 */
	const MAX_FILES = 50000;

	/**
	 * Maximum file size to hash (10 MB).
	 *
	 * @var int
	 */
	const MAX_FILE_SIZE = 10485760;

	/**
	 * Directories to exclude from scanning.
	 *
	 * @var array
	 */
	private static $excluded_dirs = array(
		'uploads',
		'cache',
		'upgrade',
		'sentinel-backups',
		'node_modules',
		'.git',
	);

	/**
	 * Constructor.
	 *
	 * @param array $settings Plugin settings.
	 */
	public function __construct( $settings = array() ) {
		$this->settings = $settings;
	}

	/**
	 * Run the file integrity scan.
	 *
	 * If no baseline exists, create one and return an info notice.
	 * Otherwise compare the current state with the baseline.
	 *
	 * @return array Array of vulnerability data arrays.
	 */
	public function scan() {
		global $wpdb;

		// Check if baseline exists.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$baseline_count = (int) $wpdb->get_var(
			"SELECT COUNT(*) FROM {$wpdb->prefix}sentinel_file_integrity" // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		);

		if ( 0 === $baseline_count ) {
			$this->create_baseline();
			return array(
				array(
					'component_type'    => 'file',
					'component_name'    => 'File Integrity',
					'component_version' => '',
					'vulnerability_id'  => 'file-monitor-baseline-created',
					'title'             => 'File integrity baseline created',
					'description'       => 'A new file integrity baseline has been established. Future scans will detect changes from this snapshot.',
					'severity'          => 'info',
					'cvss_score'        => 0.0,
					'cvss_vector'       => '',
					'recommendation'    => 'No action required.',
					'reference_urls'    => wp_json_encode( array() ),
				),
			);
		}

		return $this->compare_with_baseline();
	}

	/**
	 * Create a new baseline snapshot.
	 *
	 * @return void
	 */
	public function create_baseline() {
		global $wpdb;

		// Clear existing baseline.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$wpdb->query( "TRUNCATE TABLE {$wpdb->prefix}sentinel_file_integrity" ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared

		$count = 0;
		$now   = current_time( 'mysql' );

		foreach ( $this->get_file_iterator() as $file ) {
			if ( $count >= self::MAX_FILES ) {
				break;
			}

			if ( ! $file->isFile() || $file->getSize() > self::MAX_FILE_SIZE ) {
				continue;
			}

			$hash = hash_file( 'sha256', $file->getPathname() );
			if ( false === $hash ) {
				continue;
			}

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			$wpdb->insert(
				"{$wpdb->prefix}sentinel_file_integrity",
				array(
					'file_path'        => $file->getPathname(),
					'file_hash'        => $hash,
					'expected_hash'    => $hash,
					'file_size'        => $file->getSize(),
					'file_permissions' => substr( sprintf( '%o', $file->getPerms() ), -4 ),
					'status'           => 'clean',
					'last_checked'     => $now,
				),
				array( '%s', '%s', '%s', '%d', '%s', '%s', '%s' )
			);

			$count++;
		}
	}

	/**
	 * Compare current file state against the stored baseline.
	 *
	 * @return array Vulnerabilities found.
	 */
	public function compare_with_baseline() {
		global $wpdb;

		$vulnerabilities = array();
		$current_files   = array();
		$now             = current_time( 'mysql' );
		$count           = 0;

		foreach ( $this->get_file_iterator() as $file ) {
			if ( $count >= self::MAX_FILES ) {
				break;
			}

			if ( ! $file->isFile() || $file->getSize() > self::MAX_FILE_SIZE ) {
				continue;
			}

			$path = $file->getPathname();
			$current_files[ $path ] = true;

			$hash = hash_file( 'sha256', $path );
			if ( false === $hash ) {
				continue;
			}

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$baseline_row = $wpdb->get_row(
				$wpdb->prepare(
					"SELECT * FROM {$wpdb->prefix}sentinel_file_integrity WHERE file_path = %s",
					$path
				)
			);

			if ( ! $baseline_row ) {
				// New file — not in baseline.
				$severity = $this->classify_severity( $path );

				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
				$wpdb->insert(
					"{$wpdb->prefix}sentinel_file_integrity",
					array(
						'file_path'        => $path,
						'file_hash'        => $hash,
						'expected_hash'    => '',
						'file_size'        => $file->getSize(),
						'file_permissions' => substr( sprintf( '%o', $file->getPerms() ), -4 ),
						'status'           => 'new',
						'last_checked'     => $now,
					),
					array( '%s', '%s', '%s', '%d', '%s', '%s', '%s' )
				);

				$vulnerabilities[] = $this->build_vuln( 'new', $path, $severity );
			} elseif ( $hash !== $baseline_row->expected_hash ) {
				// File has been modified.
				$severity = $this->classify_severity( $path );

				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
				$wpdb->update(
					"{$wpdb->prefix}sentinel_file_integrity",
					array(
						'file_hash'    => $hash,
						'status'       => 'modified',
						'last_checked' => $now,
					),
					array( 'id' => $baseline_row->id ),
					array( '%s', '%s', '%s' ),
					array( '%d' )
				);

				$vulnerabilities[] = $this->build_vuln( 'modified', $path, $severity );
			} else {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
				$wpdb->update(
					"{$wpdb->prefix}sentinel_file_integrity",
					array( 'status' => 'clean', 'last_checked' => $now ),
					array( 'id' => $baseline_row->id ),
					array( '%s', '%s' ),
					array( '%d' )
				);
			}

			$count++;
		}

		// Detect deleted files.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$baseline_files = $wpdb->get_results(
			"SELECT id, file_path FROM {$wpdb->prefix}sentinel_file_integrity WHERE status != 'new'" // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		);

		foreach ( $baseline_files as $row ) {
			if ( ! isset( $current_files[ $row->file_path ] ) && ! file_exists( $row->file_path ) ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
				$wpdb->update(
					"{$wpdb->prefix}sentinel_file_integrity",
					array( 'status' => 'deleted', 'last_checked' => $now ),
					array( 'id' => $row->id ),
					array( '%s', '%s' ),
					array( '%d' )
				);

				$vulnerabilities[] = $this->build_vuln( 'deleted', $row->file_path, 'medium' );
			}
		}

		return $vulnerabilities;
	}

	/**
	 * Get a recursive iterator for all monitored files.
	 *
	 * @return RecursiveIteratorIterator
	 */
	private function get_file_iterator() {
		$filter = new class( new RecursiveDirectoryIterator( ABSPATH, RecursiveDirectoryIterator::SKIP_DOTS ), self::$excluded_dirs ) extends RecursiveFilterIterator {

			private $excluded;

			public function __construct( RecursiveDirectoryIterator $iterator, array $excluded ) {
				parent::__construct( $iterator );
				$this->excluded = $excluded;
			}

			public function accept(): bool {
				$filename = $this->current()->getFilename();
				return ! in_array( $filename, $this->excluded, true );
			}

			public function getChildren(): self {
				return new self( $this->getInnerIterator()->getChildren(), $this->excluded ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			}
		};

		return new RecursiveIteratorIterator( $filter );
	}

	/**
	 * Classify the severity of a file change based on its location.
	 *
	 * @param string $path Absolute file path.
	 * @return string Severity level.
	 */
	private function classify_severity( $path ) {
		if ( false !== strpos( $path, ABSPATH . 'wp-admin' ) || false !== strpos( $path, ABSPATH . WPINC ) ) {
			return 'critical';
		} elseif ( false !== strpos( $path, WP_PLUGIN_DIR ) ) {
			return 'high';
		} elseif ( false !== strpos( $path, WP_CONTENT_DIR . '/themes' ) ) {
			return 'medium';
		}
		return 'medium';
	}

	/**
	 * Build a vulnerability entry for a file change.
	 *
	 * @param string $change_type 'new' | 'modified' | 'deleted'.
	 * @param string $path        Absolute file path.
	 * @param string $severity    Severity level.
	 * @return array
	 */
	private function build_vuln( $change_type, $path, $severity ) {
		$relative = str_replace( ABSPATH, '', $path );

		$titles = array(
			'new'      => 'New file detected: ',
			'modified' => 'Modified file detected: ',
			'deleted'  => 'File deleted: ',
		);

		$descriptions = array(
			'new'      => 'A new file was detected that was not present in the baseline: ',
			'modified' => 'A file has been modified since the baseline was created: ',
			'deleted'  => 'A file that was in the baseline is now missing: ',
		);

		$cvss = array( 'critical' => 9.1, 'high' => 7.5, 'medium' => 5.3, 'low' => 3.0 );

		return array(
			'component_type'    => 'file',
			'component_name'    => 'File Integrity Monitor',
			'component_version' => '',
			'vulnerability_id'  => 'file-' . $change_type . '-' . md5( $path ),
			'title'             => ( $titles[ $change_type ] ?? 'File change: ' ) . $relative,
			'description'       => ( $descriptions[ $change_type ] ?? 'File changed: ' ) . $relative,
			'severity'          => $severity,
			'cvss_score'        => $cvss[ $severity ] ?? 5.0,
			'cvss_vector'       => '',
			'recommendation'    => 'Review this file for unauthorized modifications and restore from a known-good backup if necessary.',
			'reference_urls'    => wp_json_encode( array() ),
		);
	}
}
