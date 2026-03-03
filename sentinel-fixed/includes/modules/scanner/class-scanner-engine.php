<?php
/**
 * Scanner Engine — Orchestrates all scan types.
 *
 * @package WP_Sentinel_Security
 * @since   1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Scanner_Engine
 */
class Scanner_Engine {

	/**
	 * Plugin settings.
	 *
	 * @var array
	 */
	private $settings;

	/**
	 * Scanner type → sub-scanner class name map.
	 *
	 * @var array
	 */
	private static $scanner_map = array(
		'full'   => array(
			'Core_Integrity',
			'Plugin_Vulnerability',
			'Theme_Vulnerability',
			'Config_Analyzer',
			'Permission_Checker',
			'File_Monitor',
			'Malware_Detector',
			'User_Audit',
			'Database_Scanner',
			'Compliance_Checker',
			'SSL_Scanner',
			'Header_Analyzer',
		),
		'quick'  => array( 'Core_Integrity', 'Plugin_Vulnerability', 'Config_Analyzer' ),
		'core'   => array( 'Core_Integrity' ),
		'plugins' => array( 'Plugin_Vulnerability' ),
		'themes' => array( 'Theme_Vulnerability' ),
		'files'  => array( 'File_Monitor', 'Permission_Checker', 'Malware_Detector' ),
		'config' => array( 'Config_Analyzer' ),
		'user_audit' => array( 'User_Audit' ),
		'database'   => array( 'Database_Scanner' ),
		'compliance' => array( 'Compliance_Checker' ),
		'ssl'        => array( 'SSL_Scanner' ),
		'headers'    => array( 'Header_Analyzer' ),
		// Scan types exposed by the REST API.
		'malware'    => array( 'Malware_Detector', 'File_Monitor' ),
		'integrity'  => array( 'Core_Integrity', 'File_Monitor', 'Permission_Checker' ),
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
	 * Initialise the scanner: load sub-scanners, register AJAX handlers.
	 *
	 * @return void
	 */
	public function init() {
		$scanner_dir = SENTINEL_PLUGIN_DIR . 'includes/modules/scanner/';

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
			require_once $scanner_dir . $file;
		}

		// AJAX handlers (logged-in users only).
		add_action( 'wp_ajax_sentinel_start_scan',        array( $this, 'ajax_start_scan' ) );
		add_action( 'wp_ajax_sentinel_scan_progress',     array( $this, 'ajax_scan_progress' ) );
		add_action( 'wp_ajax_sentinel_cancel_scan',       array( $this, 'ajax_cancel_scan' ) );
		add_action( 'wp_ajax_sentinel_load_scan_results',         array( $this, 'ajax_load_scan_results' ) );
		add_action( 'wp_ajax_sentinel_get_open_vulnerabilities',   array( $this, 'ajax_get_open_vulnerabilities' ) );
		add_action( 'wp_ajax_sentinel_get_scan_differential',      array( $this, 'ajax_get_scan_differential' ) );
	}

	// -----------------------------------------------------------------------
	// AJAX handlers
	// -----------------------------------------------------------------------

	/**
	 * AJAX: start a new scan.
	 *
	 * @return void
	 */
	public function ajax_start_scan() {
		check_ajax_referer( 'sentinel_scan_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'wp-sentinel-security' ) ), 403 );
		}

		$scan_type = isset( $_POST['scan_type'] ) ? sanitize_text_field( wp_unslash( $_POST['scan_type'] ) ) : 'quick';

		if ( ! array_key_exists( $scan_type, self::$scanner_map ) ) {
			wp_send_json_error( array( 'message' => __( 'Invalid scan type.', 'wp-sentinel-security' ) ) );
		}

		// Raise PHP time limit so full scans don't get killed (0 = unlimited).
		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		@set_time_limit( 0 );
		ignore_user_abort( true );

		// Run scan synchronously — always. Cron-based async is unreliable in
		// containerised and non-public environments (Docker, localhost, etc.).
		$scan_id = $this->run_scan( $scan_type, 'manual' );

		if ( ! $scan_id ) {
			wp_send_json_error( array( 'message' => __( 'Failed to create scan record.', 'wp-sentinel-security' ) ) );
		}

		wp_send_json_success( array( 'scan_id' => $scan_id ) );
	}

	/**
	 * AJAX: get scan progress.
	 *
	 * @return void
	 */
	public function ajax_scan_progress() {
		check_ajax_referer( 'sentinel_scan_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'wp-sentinel-security' ) ), 403 );
		}

		$scan_id = absint( $_POST['scan_id'] ?? 0 );
		if ( ! $scan_id ) {
			wp_send_json_error( array( 'message' => __( 'Invalid scan ID.', 'wp-sentinel-security' ) ) );
		}

		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$scan = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM {$wpdb->prefix}sentinel_scans WHERE id = %d",
				$scan_id
			)
		);

		if ( ! $scan ) {
			wp_send_json_error( array( 'message' => __( 'Scan not found.', 'wp-sentinel-security' ) ) );
		}

		// Calculate pseudo-progress based on elapsed time (guard against invalid timestamp).
		$started_ts = strtotime( $scan->started_at );
		$elapsed    = ( $started_ts && $started_ts <= time() ) ? ( time() - $started_ts ) : 0;
		$progress   = min( 95, $elapsed * 5 );

		if ( in_array( $scan->status, array( 'completed', 'failed', 'cancelled' ), true ) ) {
			$progress = 100;
		}

		// Build a descriptive status text based on scan type and elapsed time.
		$scanner_phases = self::$scanner_map[ $scan->scan_type ] ?? array();
		$phase_count    = count( $scanner_phases );
		$phase_index    = min( $phase_count - 1, (int) floor( ( $progress / 100 ) * $phase_count ) );
		$phase_names    = array(
			'Core_Integrity'       => __( 'Checking core integrity…', 'wp-sentinel-security' ),
			'Plugin_Vulnerability' => __( 'Scanning plugin vulnerabilities…', 'wp-sentinel-security' ),
			'Theme_Vulnerability'  => __( 'Scanning theme vulnerabilities…', 'wp-sentinel-security' ),
			'Config_Analyzer'      => __( 'Analyzing configuration…', 'wp-sentinel-security' ),
			'Permission_Checker'   => __( 'Checking file permissions…', 'wp-sentinel-security' ),
			'File_Monitor'         => __( 'Monitoring file changes…', 'wp-sentinel-security' ),
			'Malware_Detector'     => __( 'Scanning for malware…', 'wp-sentinel-security' ),
			'User_Audit'           => __( 'Auditing user accounts…', 'wp-sentinel-security' ),
			'Database_Scanner'     => __( 'Scanning database…', 'wp-sentinel-security' ),
			'Compliance_Checker'   => __( 'Checking compliance…', 'wp-sentinel-security' ),
			'SSL_Scanner'          => __( 'Checking SSL/TLS…', 'wp-sentinel-security' ),
			'Header_Analyzer'      => __( 'Analyzing HTTP headers…', 'wp-sentinel-security' ),
		);
		$current_phase_name = isset( $scanner_phases[ $phase_index ] )
			? ( $phase_names[ $scanner_phases[ $phase_index ] ] ?? __( 'Scanning…', 'wp-sentinel-security' ) )
			: __( 'Scanning…', 'wp-sentinel-security' );
		if ( 100 === $progress ) { $current_phase_name = __( 'Scan complete!', 'wp-sentinel-security' ); }

		// Fetch vulnerabilities if completed.
		$vulnerabilities = array();
		if ( 'completed' === $scan->status ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$vulnerabilities = $wpdb->get_results(
				$wpdb->prepare(
					"SELECT * FROM {$wpdb->prefix}sentinel_vulnerabilities WHERE scan_id = %d ORDER BY cvss_score DESC",
					$scan_id
				)
			);
		}

		wp_send_json_success(
			array(
				'status'          => $scan->status,
				'progress'        => $progress,
				'status_text'     => $current_phase_name,
				'vulnerabilities' => $vulnerabilities,
			)
		);
	}

	/**
	 * AJAX: cancel a running scan.
	 *
	 * @return void
	 */
	public function ajax_cancel_scan() {
		check_ajax_referer( 'sentinel_scan_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'wp-sentinel-security' ) ), 403 );
		}

		$scan_id = absint( $_POST['scan_id'] ?? 0 );
		if ( ! $scan_id ) {
			wp_send_json_error( array( 'message' => __( 'Invalid scan ID.', 'wp-sentinel-security' ) ) );
		}

		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->update(
			"{$wpdb->prefix}sentinel_scans",
			array( 'status' => 'cancelled', 'completed_at' => current_time( 'mysql' ) ),
			array( 'id' => $scan_id ),
			array( '%s', '%s' ),
			array( '%d' )
		);

		wp_send_json_success();
	}

	/**
	 * AJAX: load vulnerability results for a past scan.
	 *
	 * @return void
	 */
	/**
	 * AJAX: return all open vulnerabilities across every scan (scoped view).
	 *
	 * Unlike ajax_load_scan_results, which returns every finding for one scan
	 * (including already-fixed items), this endpoint returns only rows whose
	 * status = 'open', regardless of which scan detected them. The result is
	 * de-duplicated by component + vulnerability_id so repeat detections from
	 * multiple scans appear only once (the most-recent row wins).
	 *
	 * @return void JSON response.
	 */
	public function ajax_get_open_vulnerabilities() {
		check_ajax_referer( 'sentinel_scan_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'wp-sentinel-security' ) ), 403 );
		}

		global $wpdb;
		$table = "{$wpdb->prefix}sentinel_vulnerabilities";

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT v.*
				 FROM {$table} v
				 INNER JOIN (
				     SELECT MAX(id) AS max_id
				     FROM {$table}
				     WHERE status = %s
				     GROUP BY component_name, COALESCE(NULLIF(vulnerability_id,''), title)
				 ) dedup ON v.id = dedup.max_id
				 ORDER BY
				     FIELD(v.severity, %s, %s, %s, %s, %s),
				     v.cvss_score DESC",
				'open',
				'critical', 'high', 'medium', 'low', 'info'
			)
		);

		$by_severity = array( 'critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0 );
		foreach ( $rows as $row ) {
			if ( isset( $by_severity[ $row->severity ] ) ) {
				$by_severity[ $row->severity ]++;
			}
		}

		wp_send_json_success( array(
			'vulnerabilities' => $rows,
			'total'           => count( $rows ),
			'by_severity'     => $by_severity,
		) );
	}

	/**
	 * AJAX: compute a differential between the two most-recent completed scans.
	 *
	 * Returns three lists:
	 *  - new      vulnerabilities present in the latest scan but not the previous
	 *  - resolved vulnerabilities present in the previous scan but now fixed/absent
	 *  - persisting vulnerabilities present in both (still open)
	 *
	 * Two findings are considered the "same" when they share both component_name
	 * and vulnerability_id (or title when vulnerability_id is empty).
	 *
	 * @return void JSON response.
	 */
	public function ajax_get_scan_differential() {
		check_ajax_referer( 'sentinel_scan_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'wp-sentinel-security' ) ), 403 );
		}

		global $wpdb;
		$scans_table = "{$wpdb->prefix}sentinel_scans";
		$vulns_table = "{$wpdb->prefix}sentinel_vulnerabilities";

		// Fetch the two most-recent completed scans.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$recent = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT id, scan_type, completed_at, vulnerabilities_found, risk_score
				 FROM {$scans_table}
				 WHERE status = %s
				 ORDER BY completed_at DESC
				 LIMIT 2",
				'completed'
			)
		);

		if ( count( $recent ) < 2 ) {
			wp_send_json_error( array(
				'message' => __( 'At least two completed scans are needed for a comparison.', 'wp-sentinel-security' ),
				'code'    => 'insufficient_scans',
			) );
		}

		$latest_scan   = $recent[0];
		$previous_scan = $recent[1];

		// Load open vulnerabilities for each scan.
		$fetch = function( $scan_id ) use ( $wpdb, $vulns_table ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			return $wpdb->get_results(
				$wpdb->prepare(
					"SELECT * FROM {$vulns_table}
					 WHERE scan_id = %d AND status = 'open'
					 ORDER BY cvss_score DESC",
					$scan_id
				)
			);
		};

		$latest_vulns   = $fetch( $latest_scan->id );
		$previous_vulns = $fetch( $previous_scan->id );

		// Build lookup keys: component_name + separator + (vulnerability_id or title).
		$key = function( $v ) {
			$id_part = ! empty( $v->vulnerability_id ) ? $v->vulnerability_id : $v->title;
			return $v->component_name . '||' . $id_part;
		};

		$latest_keys   = array();
		foreach ( $latest_vulns as $v ) {
			$latest_keys[ $key( $v ) ] = $v;
		}

		$previous_keys = array();
		foreach ( $previous_vulns as $v ) {
			$previous_keys[ $key( $v ) ] = $v;
		}

		$new_keys        = array_diff_key( $latest_keys,   $previous_keys );
		$resolved_keys   = array_diff_key( $previous_keys, $latest_keys );
		$persisting_keys = array_intersect_key( $latest_keys, $previous_keys );

		wp_send_json_success( array(
			'latest_scan'   => $latest_scan,
			'previous_scan' => $previous_scan,
			'summary'       => array(
				'new'        => count( $new_keys ),
				'resolved'   => count( $resolved_keys ),
				'persisting' => count( $persisting_keys ),
				'score_delta' => (float) $latest_scan->risk_score - (float) $previous_scan->risk_score,
			),
			'new'        => array_values( $new_keys ),
			'resolved'   => array_values( $resolved_keys ),
			'persisting' => array_values( $persisting_keys ),
		) );
	}

	public function ajax_load_scan_results() {
		check_ajax_referer( 'sentinel_scan_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'wp-sentinel-security' ) ), 403 );
		}

		$scan_id = absint( $_POST['scan_id'] ?? 0 );
		if ( ! $scan_id ) {
			wp_send_json_error( array( 'message' => __( 'Invalid scan ID.', 'wp-sentinel-security' ) ) );
		}

		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$scan = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM {$wpdb->prefix}sentinel_scans WHERE id = %d",
				$scan_id
			)
		);

		if ( ! $scan ) {
			wp_send_json_error( array( 'message' => __( 'Scan not found.', 'wp-sentinel-security' ) ) );
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$vulnerabilities = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$wpdb->prefix}sentinel_vulnerabilities WHERE scan_id = %d ORDER BY cvss_score DESC",
				$scan_id
			)
		);

		wp_send_json_success(
			array(
				'scan'            => $scan,
				'vulnerabilities' => $vulnerabilities,
			)
		);
	}

	// -----------------------------------------------------------------------
	// Core scan runner
	// -----------------------------------------------------------------------

	/**
	 * Run a scan of the given type.
	 *
	 * @param string $type         Scan type key.
	 * @param string $triggered_by How the scan was triggered (manual|cron).
	 * @param int    $scan_id      Existing scan row ID, or 0 to create one.
	 * @return int Scan row ID.
	 */
	public function run_scan( $type, $triggered_by = 'manual', $scan_id = 0 ) {
		global $wpdb;

		if ( ! $scan_id ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			$inserted = $wpdb->insert(
				"{$wpdb->prefix}sentinel_scans",
				array(
					'scan_type'    => $type,
					'status'       => 'running',
					'started_at'   => current_time( 'mysql' ),
					'triggered_by' => $triggered_by,
				),
				array( '%s', '%s', '%s', '%s' )
			);

			if ( false === $inserted || ! $wpdb->insert_id ) {
				// Cannot continue without a valid scan row — fail early.
				error_log( 'WP Sentinel: Failed to create scan record in the database.' ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
				return 0;
			}

			$scan_id = $wpdb->insert_id;
		} else {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$wpdb->update(
				"{$wpdb->prefix}sentinel_scans",
				array( 'status' => 'running' ),
				array( 'id' => $scan_id ),
				array( '%s' ),
				array( '%d' )
			);
		}

		$scanners    = self::$scanner_map[ $type ] ?? self::$scanner_map['quick'];
		$all_vulns   = array();
		$total_checks = 0;

		try {

		foreach ( $scanners as $scanner_class ) {
			if ( ! class_exists( $scanner_class ) ) {
				continue;
			}

			try {
				$scanner = new $scanner_class( $this->settings );
				$results = $scanner->scan();

				foreach ( $results as $vuln ) {
					$all_vulns[]  = $vuln;
					$total_checks++;
				}
			} catch ( Exception $e ) {
				// Log but continue scanning remaining modules.
				error_log( 'WP Sentinel: Scanner error in ' . $scanner_class . ': ' . $e->getMessage() ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			}
		}

		// Save vulnerabilities.
		foreach ( $all_vulns as $vuln ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			$wpdb->insert(
				"{$wpdb->prefix}sentinel_vulnerabilities",
				array_merge(
					$vuln,
					array(
						'scan_id'     => $scan_id,
						'detected_at' => current_time( 'mysql' ),
						'status'      => 'open',
					)
				),
				null
			);
		}

		$risk_score = $this->calculate_risk_score( $all_vulns );

		// Summarize by severity.
		$by_severity = array_count_values( array_column( $all_vulns, 'severity' ) );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->update(
			"{$wpdb->prefix}sentinel_scans",
			array(
				'status'               => 'completed',
				'completed_at'         => current_time( 'mysql' ),
				'total_checks'         => $total_checks,
				'vulnerabilities_found' => count( $all_vulns ),
				'risk_score'           => $risk_score,
				'summary'              => wp_json_encode( $by_severity ),
			),
			array( 'id' => $scan_id ),
			array( '%s', '%s', '%d', '%d', '%f', '%s' ),
			array( '%d' )
		);

		} catch ( Throwable $fatal ) {
			// Uncaught error/exception at the orchestration level — mark the scan
			// as failed so it does not hang indefinitely in 'running' state.
			error_log( 'WP Sentinel: Fatal scan error: ' . $fatal->getMessage() ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$wpdb->update(
				"{$wpdb->prefix}sentinel_scans",
				array(
					'status'       => 'failed',
					'completed_at' => current_time( 'mysql' ),
				),
				array( 'id' => $scan_id ),
				array( '%s', '%s' ),
				array( '%d' )
			);
		}

		return $scan_id;
	}

	/**
	 * Calculate risk score based on vulnerabilities found.
	 *
	 * @param array $vulnerabilities Array of vulnerability data arrays.
	 * @return float Risk score (0-100).
	 */
	private function calculate_risk_score( $vulnerabilities ) {
		$score = 100.0;

		$penalties = array(
			'critical' => 25,
			'high'     => 15,
			'medium'   => 8,
			'low'      => 3,
		);

		foreach ( $vulnerabilities as $v ) {
			$sev   = $v['severity'] ?? 'info';
			$score -= $penalties[ $sev ] ?? 0;
		}

		return max( 0.0, min( 100.0, $score ) );
	}
}
