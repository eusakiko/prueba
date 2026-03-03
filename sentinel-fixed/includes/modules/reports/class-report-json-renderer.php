<?php
/**
 * JSON report renderer.
 *
 * Produces a pretty-printed JSON string from structured report data.
 *
 * @package WP_Sentinel_Security
 * @since   2.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Report_JSON_Renderer
 */
class Report_JSON_Renderer {

	/**
	 * Render report data as a pretty-printed JSON string.
	 *
	 * Expected keys in $data:
	 *  - metadata        array  generated_at, report_type, schema_version, site_url, company_name
	 *  - scan_results    array  summary stats
	 *  - vulnerabilities array  vulnerability objects/arrays
	 *  - hardening_status array hardening check objects/arrays
	 *
	 * @param array $data Report data.
	 * @return string JSON-encoded report.
	 */
	public function render( $data ) {
		$payload = array(
			'metadata'         => array(
				'schema_version' => '2.0.0',
				'generated_at'   => isset( $data['metadata']['generated_at'] ) ? $data['metadata']['generated_at'] : current_time( 'c' ),
				'report_type'    => isset( $data['metadata']['report_type'] ) ? sanitize_text_field( $data['metadata']['report_type'] ) : 'full',
				'site_url'       => isset( $data['metadata']['site_url'] ) ? esc_url_raw( $data['metadata']['site_url'] ) : get_site_url(),
				'company_name'   => isset( $data['metadata']['company_name'] ) ? sanitize_text_field( $data['metadata']['company_name'] ) : '',
			),
			'scan_results'     => isset( $data['scan_results'] ) ? $data['scan_results'] : array(),
			'vulnerabilities'  => isset( $data['vulnerabilities'] ) ? $data['vulnerabilities'] : array(),
			'hardening_status' => isset( $data['hardening_status'] ) ? $data['hardening_status'] : array(),
		);

		return wp_json_encode( $payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
	}
}
