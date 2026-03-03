<?php
/**
 * CSV report renderer.
 *
 * Produces UTF-8 BOM CSV strings for vulnerabilities and hardening checks.
 *
 * @package WP_Sentinel_Security
 * @since   2.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Report_CSV_Renderer
 */
class Report_CSV_Renderer {

	/**
	 * UTF-8 Byte Order Mark.
	 *
	 * @var string
	 */
	private $bom = "\xEF\xBB\xBF";

	/**
	 * Escape a single CSV field value.
	 *
	 * Wraps the value in double-quotes and escapes any existing double-quotes.
	 *
	 * @param string $value Raw field value.
	 * @return string Escaped CSV field.
	 */
	private function csv_field( $value ) {
		$value = (string) $value;
		$value = str_replace( '"', '""', $value );
		return '"' . $value . '"';
	}

	/**
	 * Build a CSV row from an array of values.
	 *
	 * @param array $fields Array of field values.
	 * @return string Comma-separated row terminated by CRLF.
	 */
	private function csv_row( $fields ) {
		return implode( ',', array_map( array( $this, 'csv_field' ), $fields ) ) . "\r\n";
	}

	/**
	 * Render vulnerabilities as a CSV string.
	 *
	 * Columns: ID, Component, Type, Version, Vulnerability, Severity, CVSS Score, Status,
	 *          Detected, Recommendation
	 *
	 * @param array $vulnerabilities Array of vulnerability objects or arrays.
	 * @return string CSV content with UTF-8 BOM.
	 */
	public function render_vulnerabilities( $vulnerabilities ) {
		$output = $this->bom;

		$output .= $this->csv_row(
			array(
				'ID',
				'Component',
				'Type',
				'Version',
				'Vulnerability',
				'Severity',
				'CVSS Score',
				'Status',
				'Detected',
				'Recommendation',
			)
		);

		foreach ( $vulnerabilities as $v ) {
			$v = (array) $v;
			$output .= $this->csv_row(
				array(
					$v['id'] ?? '',
					$v['component_name'] ?? '',
					$v['component_type'] ?? '',
					$v['component_version'] ?? '',
					$v['title'] ?? '',
					$v['severity'] ?? '',
					$v['cvss_score'] ?? '',
					$v['status'] ?? '',
					$v['detected_at'] ?? '',
					$v['recommendation'] ?? '',
				)
			);
		}

		return $output;
	}

	/**
	 * Render hardening checks as a CSV string.
	 *
	 * Columns: Check ID, Name, Category, Status, Risk Level, Description
	 *
	 * @param array $checks Array of hardening check objects or arrays.
	 * @return string CSV content with UTF-8 BOM.
	 */
	public function render_hardening( $checks ) {
		$output = $this->bom;

		$output .= $this->csv_row(
			array(
				'Check ID',
				'Name',
				'Category',
				'Status',
				'Risk Level',
				'Description',
			)
		);

		foreach ( $checks as $c ) {
			$c = (array) $c;
			$output .= $this->csv_row(
				array(
					$c['id'] ?? $c['check_id'] ?? '',
					$c['name'] ?? $c['check_name'] ?? '',
					$c['category'] ?? '',
					$c['status'] ?? '',
					$c['risk_level'] ?? $c['severity'] ?? '',
					$c['description'] ?? '',
				)
			);
		}

		return $output;
	}
}
