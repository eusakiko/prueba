<?php
/**
 * WP-CLI commands for WP Sentinel Security.
 *
 * Provides `wp sentinel scan`, `wp sentinel harden`, and `wp sentinel status`
 * sub-commands for command-line management and CI/CD automation.
 *
 * @package WP_Sentinel_Security
 * @since   2.1.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
	return;
}

/**
 * WP Sentinel Security — command-line security management.
 *
 * ## EXAMPLES
 *
 *     # Run a quick security scan.
 *     wp sentinel scan --type=quick
 *
 *     # Show current security status.
 *     wp sentinel status
 *
 *     # Apply all recommended hardening rules.
 *     wp sentinel harden --apply
 */
class Sentinel_CLI {

	/**
	 * Run a security scan.
	 *
	 * ## OPTIONS
	 *
	 * [--type=<type>]
	 * : Scan type to run. Accepts: quick, full, malware, integrity.
	 * ---
	 * default: full
	 * options:
	 *   - quick
	 *   - full
	 *   - malware
	 *   - integrity
	 * ---
	 *
	 * [--format=<format>]
	 * : Output format. Accepts: table, json, csv.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - csv
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp sentinel scan
	 *     wp sentinel scan --type=malware --format=json
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 * @return void
	 */
	public function scan( $args, $assoc_args ) {
		$type   = $assoc_args['type'] ?? 'full';
		$format = $assoc_args['format'] ?? 'table';

		WP_CLI::log( sprintf( 'Starting %s scan...', $type ) );

		$core = Sentinel_Core::get_instance();

		try {
			$scanner = new Scanner_Engine( $core->get_settings() );
			$results = $scanner->run_scan( $type );
		} catch ( \Throwable $e ) {
			WP_CLI::error( $e->getMessage() );
			return;
		}

		if ( empty( $results ) || ( is_array( $results ) && empty( $results['vulnerabilities'] ?? $results ) ) ) {
			WP_CLI::success( 'No vulnerabilities found.' );
			return;
		}

		$vulns = $results['vulnerabilities'] ?? $results;

		if ( ! is_array( $vulns ) ) {
			WP_CLI::success( 'Scan complete.' );
			return;
		}

		$items = array();
		foreach ( $vulns as $vuln ) {
			$items[] = array(
				'ID'       => $vuln['vulnerability_id'] ?? '',
				'Title'    => $vuln['title'] ?? '',
				'Severity' => $vuln['severity'] ?? '',
				'CVSS'     => $vuln['cvss_score'] ?? '',
			);
		}

		WP_CLI\Utils\format_items( $format, $items, array( 'ID', 'Title', 'Severity', 'CVSS' ) );

		WP_CLI::log( sprintf( '%d vulnerabilities found.', count( $items ) ) );
	}

	/**
	 * Show current security status and score.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : Output format. Accepts: table, json, yaml.
	 * ---
	 * default: table
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp sentinel status
	 *     wp sentinel status --format=json
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 * @return void
	 */
	public function status( $args, $assoc_args ) {
		$format = $assoc_args['format'] ?? 'table';

		$core     = Sentinel_Core::get_instance();
		$settings = $core->get_settings();

		$status_data = array(
			array( 'Key' => 'Plugin Version', 'Value' => SENTINEL_VERSION ),
			array( 'Key' => 'PHP Version', 'Value' => PHP_VERSION ),
			array( 'Key' => 'Scan Frequency', 'Value' => $settings['scan_frequency'] ?? 'daily' ),
			array( 'Key' => 'WAF Enabled', 'Value' => ! empty( $settings['waf_enabled'] ) ? 'Yes' : 'No' ),
			array( 'Key' => '2FA Available', 'Value' => ! empty( $settings['2fa_enabled'] ) ? 'Yes' : 'No' ),
			array( 'Key' => 'Alert Channels', 'Value' => implode( ', ', $settings['alert_channels'] ?? array( 'email' ) ) ),
			array( 'Key' => 'Log Retention', 'Value' => ( $settings['log_retention_days'] ?? 90 ) . ' days' ),
		);

		WP_CLI\Utils\format_items( $format, $status_data, array( 'Key', 'Value' ) );
	}

	/**
	 * Manage hardening rules.
	 *
	 * ## OPTIONS
	 *
	 * [--apply]
	 * : Apply recommended hardening rules.
	 *
	 * [--revert]
	 * : Revert all hardening rules.
	 *
	 * [--status]
	 * : Show current hardening status.
	 *
	 * ## EXAMPLES
	 *
	 *     wp sentinel harden --status
	 *     wp sentinel harden --apply
	 *     wp sentinel harden --revert
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 * @return void
	 */
	public function harden( $args, $assoc_args ) {
		$core     = Sentinel_Core::get_instance();
		$settings = $core->get_settings();

		$engine = new Hardening_Engine( $settings );

		if ( ! empty( $assoc_args['apply'] ) ) {
			WP_CLI::log( 'Applying hardening rules...' );

			try {
				$results = $engine->apply_all();
				if ( is_array( $results ) ) {
					foreach ( $results as $check_id => $result ) {
						$status_text = $result['status'] ?? 'unknown';
						WP_CLI::log( sprintf( '  %s: %s', $check_id, $status_text ) );
					}
				}
				WP_CLI::success( 'Hardening rules applied.' );
			} catch ( \Throwable $e ) {
				WP_CLI::error( $e->getMessage() );
			}
			return;
		}

		if ( ! empty( $assoc_args['revert'] ) ) {
			WP_CLI::log( 'Reverting hardening rules...' );

			try {
				$results = $engine->revert_all();
				if ( is_array( $results ) ) {
					foreach ( $results as $check_id => $result ) {
						$status_text = $result['status'] ?? 'unknown';
						WP_CLI::log( sprintf( '  %s: %s', $check_id, $status_text ) );
					}
				}
				WP_CLI::success( 'Hardening rules reverted.' );
			} catch ( \Throwable $e ) {
				WP_CLI::error( $e->getMessage() );
			}
			return;
		}

		// Default: show status.
		WP_CLI::log( 'Current hardening status:' );

		try {
			$statuses = $engine->get_status();
			if ( is_array( $statuses ) ) {
				$items = array();
				foreach ( $statuses as $check_id => $info ) {
					$items[] = array(
						'Rule'    => $check_id,
						'Status'  => $info['status'] ?? 'unknown',
						'Details' => $info['details'] ?? '',
					);
				}
				WP_CLI\Utils\format_items( 'table', $items, array( 'Rule', 'Status', 'Details' ) );
			}
		} catch ( \Throwable $e ) {
			WP_CLI::error( $e->getMessage() );
		}
	}
}

WP_CLI::add_command( 'sentinel', 'Sentinel_CLI' );
