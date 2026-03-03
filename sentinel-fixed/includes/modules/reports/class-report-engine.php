<?php
/**
 * Report engine.
 *
 * Orchestrates report generation, persistence, and delivery.
 * Registers AJAX handlers for the admin reports interface.
 *
 * @package WP_Sentinel_Security
 * @since   2.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Report_Engine
 */
class Report_Engine {

	/**
	 * Plugin settings.
	 *
	 * @var array
	 */
	private $settings;

	/**
	 * JSON renderer instance.
	 *
	 * @var Report_JSON_Renderer
	 */
	private $json_renderer;

	/**
	 * CSV renderer instance.
	 *
	 * @var Report_CSV_Renderer
	 */
	private $csv_renderer;

	/**
	 * HTML renderer instance.
	 *
	 * @var Report_HTML_Renderer
	 */
	private $html_renderer;

	/**
	 * Constructor.
	 *
	 * @param array $settings Plugin settings.
	 */
	public function __construct( $settings = array() ) {
		$this->settings = $settings;
	}

	/**
	 * Initialize the engine: load renderers and register AJAX hooks.
	 *
	 * @return void
	 */
	public function init() {
		$base = SENTINEL_PLUGIN_DIR . 'includes/modules/reports/';
		require_once $base . 'class-report-json-renderer.php';
		require_once $base . 'class-report-csv-renderer.php';
		require_once $base . 'class-report-html-renderer.php';

		$this->json_renderer = new Report_JSON_Renderer();
		$this->csv_renderer  = new Report_CSV_Renderer();
		$this->html_renderer = new Report_HTML_Renderer();

		add_action( 'wp_ajax_sentinel_generate_report', array( $this, 'ajax_generate_report' ) );
		add_action( 'wp_ajax_sentinel_get_reports',     array( $this, 'ajax_get_reports' ) );
		add_action( 'wp_ajax_sentinel_delete_report',   array( $this, 'ajax_delete_report' ) );
		add_action( 'wp_ajax_sentinel_download_report', array( $this, 'ajax_download_report' ) );
	}

	/**
	 * Generate and persist a report.
	 *
	 * @param string $type    Report type: 'technical', 'executive', 'compliance'.
	 * @param string $format  Output format: 'html', 'json', 'csv'.
	 * @param array  $options Optional overrides (scan_id, company_name, etc.).
	 * @return int|WP_Error Report ID on success, WP_Error on failure.
	 */
	public function generate_report( $type, $format, $options = array() ) {
		$allowed_types   = array( 'technical', 'executive', 'compliance' );
		$allowed_formats = array( 'html', 'json', 'csv' );

		$type   = in_array( $type, $allowed_types, true ) ? $type : 'technical';
		$format = in_array( $format, $allowed_formats, true ) ? $format : 'html';

		$data = $this->collect_data( $type, $options );

		switch ( $format ) {
			case 'json':
				$content   = $this->json_renderer->render( $data );
				$extension = 'json';
				$mime      = 'application/json';
				break;

			case 'csv':
				$content   = $this->csv_renderer->render_vulnerabilities( $data['vulnerabilities'] ?? array() );
				$extension = 'csv';
				$mime      = 'text/csv';
				break;

			default: // html.
				switch ( $type ) {
					case 'executive':
						$content = $this->html_renderer->render_executive( $data );
						break;
					case 'compliance':
						$content = $this->html_renderer->render_compliance( $data );
						break;
					default:
						$content = $this->html_renderer->render_technical( $data );
						break;
				}
				$extension = 'html';
				$mime      = 'text/html';
				break;
		}

		// Ensure upload directory exists.
		$upload_dir = WP_CONTENT_DIR . '/uploads/sentinel-reports/';
		if ( ! file_exists( $upload_dir ) ) {
			wp_mkdir_p( $upload_dir );
			// Protect the directory for both Apache 2.2 and 2.4+.
			$htaccess = "<IfModule mod_authz_core.c>\n\tRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n\tDeny from all\n</IfModule>";
			file_put_contents( $upload_dir . '.htaccess', $htaccess ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		}

		$filename  = sprintf( 'sentinel-report-%s-%s-%s.%s', $type, $format, gmdate( 'Ymd-His' ), $extension );
		$file_path = $upload_dir . $filename;

		$result = file_put_contents( $file_path, $content ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		if ( false === $result ) {
			return new WP_Error( 'report_write_failed', __( 'Failed to write report file.', 'wp-sentinel-security' ) );
		}

		$company_name = sanitize_text_field( $this->settings['company_name'] ?? '' );
		$report_id    = Sentinel_DB::save_report(
			array(
				'report_type'     => $type,
				'title'           => sprintf(
					/* translators: 1: Report type, 2: Date */
					__( '%1$s Security Report — %2$s', 'wp-sentinel-security' ),
					ucfirst( $type ),
					current_time( 'Y-m-d' )
				),
				'format'          => $format,
				'file_path'       => $file_path,
				'scan_ids'        => array(),
				'branding_config' => array( 'company_name' => $company_name ),
				'generated_by'    => get_current_user_id(),
			)
		);

		if ( ! $report_id ) {
			return new WP_Error( 'report_db_failed', __( 'Failed to save report record.', 'wp-sentinel-security' ) );
		}

		return $report_id;
	}

	/**
	 * Collect report data from the database.
	 *
	 * @param string $type    Report type.
	 * @param array  $options Optional overrides.
	 * @return array
	 */
	private function collect_data( $type, $options = array() ) {
		$latest_scan = Sentinel_DB::get_latest_scan();
		$vulns       = Sentinel_DB::get_open_vulnerabilities();
		$hardening   = Sentinel_DB::get_hardening_status();
		$vuln_summary = Sentinel_DB::get_vulnerability_summary();

		$company_name = sanitize_text_field( $this->settings['company_name'] ?? '' );

		return array(
			'metadata'         => array(
				'generated_at'   => current_time( 'Y-m-d H:i:s' ),
				'report_type'    => $type,
				'schema_version' => '2.0.0',
				'site_url'       => get_site_url(),
				'company_name'   => $company_name,
			),
			'scan_results'     => array(
				'scan_id'             => $latest_scan ? $latest_scan->id : null,
				'completed_at'        => $latest_scan ? $latest_scan->completed_at : null,
				'risk_score'          => $latest_scan ? $latest_scan->risk_score : 0,
				'vulnerabilities_found' => $latest_scan ? $latest_scan->vulnerabilities_found : 0,
				'by_severity'         => $vuln_summary,
			),
			'vulnerabilities'  => $vulns,
			'hardening_checks' => $hardening,
			'settings'         => array(
				'company_name' => $company_name,
				'company_logo' => $this->settings['company_logo'] ?? '',
			),
		);
	}

	/**
	 * Get a paginated list of reports.
	 *
	 * @param int $page     Page number (1-based).
	 * @param int $per_page Items per page.
	 * @return array {items: array, total: int, pages: int}
	 */
	public function get_reports( $page = 1, $per_page = 20 ) {
		return Sentinel_DB::get_reports( $page, $per_page );
	}

	/**
	 * Delete a report record and its associated file.
	 *
	 * @param int $report_id Report ID.
	 * @return bool True on success, false on failure.
	 */
	public function delete_report( $report_id ) {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$report = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM {$wpdb->prefix}sentinel_reports WHERE id = %d",
				absint( $report_id )
			)
		);

		if ( ! $report ) {
			return false;
		}

		if ( ! empty( $report->file_path ) && file_exists( $report->file_path ) ) {
			unlink( $report->file_path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
		}

		return (bool) Sentinel_DB::delete_report( $report_id );
	}

	// -------------------------------------------------------------------------
	// AJAX handlers
	// -------------------------------------------------------------------------

	/**
	 * AJAX: generate a new report.
	 *
	 * @return void
	 */
	public function ajax_generate_report() {
		check_ajax_referer( 'sentinel_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'wp-sentinel-security' ) ), 403 );
		}

		$type   = isset( $_POST['type'] ) ? sanitize_text_field( wp_unslash( $_POST['type'] ) ) : 'technical';
		$format = isset( $_POST['format'] ) ? sanitize_text_field( wp_unslash( $_POST['format'] ) ) : 'html';

		$result = $this->generate_report( $type, $format );

		if ( is_wp_error( $result ) ) {
			wp_send_json_error( array( 'message' => $result->get_error_message() ) );
		}

		wp_send_json_success( array( 'report_id' => $result, 'message' => __( 'Report generated successfully.', 'wp-sentinel-security' ) ) );
	}

	/**
	 * AJAX: get paginated report list.
	 *
	 * @return void
	 */
	public function ajax_get_reports() {
		check_ajax_referer( 'sentinel_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'wp-sentinel-security' ) ), 403 );
		}

		$page     = isset( $_GET['page'] ) ? absint( $_GET['page'] ) : 1;
		$per_page = isset( $_GET['per_page'] ) ? absint( $_GET['per_page'] ) : 20;

		wp_send_json_success( $this->get_reports( $page, $per_page ) );
	}

	/**
	 * AJAX: delete a report.
	 *
	 * @return void
	 */
	public function ajax_delete_report() {
		check_ajax_referer( 'sentinel_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'wp-sentinel-security' ) ), 403 );
		}

		$report_id = isset( $_POST['report_id'] ) ? absint( $_POST['report_id'] ) : 0;

		if ( ! $report_id ) {
			wp_send_json_error( array( 'message' => __( 'Invalid report ID.', 'wp-sentinel-security' ) ) );
		}

		if ( $this->delete_report( $report_id ) ) {
			wp_send_json_success( array( 'message' => __( 'Report deleted.', 'wp-sentinel-security' ) ) );
		} else {
			wp_send_json_error( array( 'message' => __( 'Failed to delete report.', 'wp-sentinel-security' ) ) );
		}
	}

	/**
	 * AJAX: stream/download a report file.
	 *
	 * @return void
	 */
	public function ajax_download_report() {
		check_ajax_referer( 'sentinel_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Insufficient permissions.', 'wp-sentinel-security' ), 403 );
		}

		$report_id = isset( $_GET['report_id'] ) ? absint( $_GET['report_id'] ) : 0;

		if ( ! $report_id ) {
			wp_die( esc_html__( 'Invalid report ID.', 'wp-sentinel-security' ) );
		}

		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$report = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM {$wpdb->prefix}sentinel_reports WHERE id = %d",
				$report_id
			)
		);

		if ( ! $report || empty( $report->file_path ) || ! file_exists( $report->file_path ) ) {
			wp_die( esc_html__( 'Report file not found.', 'wp-sentinel-security' ) );
		}

		$mime_types = array(
			'html' => 'text/html',
			'json' => 'application/json',
			'csv'  => 'text/csv',
		);
		$mime = $mime_types[ $report->format ] ?? 'application/octet-stream';

		header( 'Content-Type: ' . $mime );
		header( 'Content-Disposition: attachment; filename="' . basename( $report->file_path ) . '"' );
		header( 'Content-Length: ' . filesize( $report->file_path ) );
		readfile( $report->file_path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_readfile
		exit;
	}
}
