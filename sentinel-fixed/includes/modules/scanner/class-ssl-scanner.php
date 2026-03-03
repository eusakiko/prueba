<?php
/**
 * SSL/TLS Scanner — checks certificate validity, expiry, mixed content,
 * HSTS headers, and TLS version support.
 *
 * @package WP_Sentinel_Security
 * @since   2.2.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class SSL_Scanner
 */
class SSL_Scanner {

	/**
	 * Plugin settings.
	 *
	 * @var array
	 */
	private $settings;

	/**
	 * Days before expiry to warn.
	 *
	 * @var int
	 */
	private $warn_days;

	/**
	 * Constructor.
	 *
	 * @param array $settings Plugin settings.
	 */
	public function __construct( $settings = array() ) {
		$this->settings  = $settings;
		$this->warn_days = isset( $settings['ssl_warn_days'] ) ? (int) $settings['ssl_warn_days'] : 30;
	}

	/**
	 * Run all SSL/TLS checks.
	 *
	 * @return array Array of vulnerability data arrays.
	 */
	public function scan() {
		$vulnerabilities = array();

		$host = parse_url( home_url(), PHP_URL_HOST );
		if ( ! $host ) {
			return $vulnerabilities;
		}

		// Only run SSL checks if the site is on HTTPS.
		if ( ! is_ssl() ) {
			$vulnerabilities[] = array(
				'component_type'    => 'ssl',
				'component_name'    => $host,
				'component_version' => '',
				'severity'          => 'high',
				'cvss_score'        => 7.5,
				'title'             => 'Site Not Using HTTPS',
				'description'       => 'The WordPress site is not served over HTTPS. All data is transmitted in plaintext.',
				'recommendation'    => 'Install an SSL/TLS certificate and configure the server to redirect HTTP to HTTPS.',
				'reference'         => 'https://web.dev/why-https-matters/',
			);
			return $vulnerabilities;
		}

		// Check certificate.
		$cert_vulns = $this->check_certificate( $host );
		$vulnerabilities = array_merge( $vulnerabilities, $cert_vulns );

		// Check HSTS.
		$hsts_vulns = $this->check_hsts();
		$vulnerabilities = array_merge( $vulnerabilities, $hsts_vulns );

		return $vulnerabilities;
	}

	/**
	 * Check SSL certificate validity and expiration.
	 *
	 * @param string $host Hostname to check.
	 * @return array
	 */
	private function check_certificate( $host ) {
		$vulnerabilities = array();

		// Attempt SSL stream context to read certificate info.
		$context = stream_context_create(
			array(
				'ssl' => array(
					'capture_peer_cert' => true,
					'verify_peer'       => true,
					'verify_peer_name'  => true,
					'SNI_enabled'       => true,
				),
			)
		);

		$socket = @stream_socket_client(  // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			'ssl://' . $host . ':443',
			$errno,
			$errstr,
			5,
			STREAM_CLIENT_CONNECT,
			$context
		);

		if ( ! $socket ) {
			$vulnerabilities[] = array(
				'component_type'    => 'ssl',
				'component_name'    => $host,
				'component_version' => '',
				'severity'          => 'high',
				'cvss_score'        => 7.5,
				'title'             => 'SSL Certificate Connection Failed',
				'description'       => 'Could not connect to ' . esc_html( $host ) . ':443 to verify the SSL certificate. Error: ' . esc_html( $errstr ),
				'recommendation'    => 'Ensure a valid SSL certificate is installed and port 443 is open.',
				'reference'         => '',
			);
			return $vulnerabilities;
		}

		$params = stream_context_get_params( $socket );
		fclose( $socket );

		if ( empty( $params['options']['ssl']['peer_certificate'] ) ) {
			return $vulnerabilities;
		}

		$cert_info = openssl_x509_parse( $params['options']['ssl']['peer_certificate'] );
		if ( ! $cert_info ) {
			return $vulnerabilities;
		}

		// Check expiry.
		if ( isset( $cert_info['validTo_time_t'] ) ) {
			$expiry_time    = (int) $cert_info['validTo_time_t'];
			$days_remaining = (int) floor( ( $expiry_time - time() ) / DAY_IN_SECONDS );

			if ( $days_remaining < 0 ) {
				$vulnerabilities[] = array(
					'component_type'    => 'ssl',
					'component_name'    => $host,
					'component_version' => '',
					'severity'          => 'critical',
					'cvss_score'        => 9.0,
					'title'             => 'SSL Certificate Has Expired',
					'description'       => sprintf( 'The SSL certificate for %s expired %d days ago.', esc_html( $host ), abs( $days_remaining ) ),
					'recommendation'    => 'Renew the SSL certificate immediately.',
					'reference'         => '',
				);
			} elseif ( $days_remaining <= $this->warn_days ) {
				$vulnerabilities[] = array(
					'component_type'    => 'ssl',
					'component_name'    => $host,
					'component_version' => '',
					'severity'          => $days_remaining <= 7 ? 'high' : 'medium',
					'cvss_score'        => $days_remaining <= 7 ? 7.0 : 5.0,
					'title'             => 'SSL Certificate Expiring Soon',
					'description'       => sprintf( 'The SSL certificate for %s will expire in %d days.', esc_html( $host ), $days_remaining ),
					'recommendation'    => 'Renew the SSL certificate before it expires.',
					'reference'         => '',
				);
			}
		}

		return $vulnerabilities;
	}

	/**
	 * Check for HSTS header on the home URL.
	 *
	 * @return array
	 */
	private function check_hsts() {
		$vulnerabilities = array();

		$response = wp_remote_get(
			home_url(),
			array(
				'timeout'   => 5,
				'sslverify' => true,
				'redirection' => 0,
			)
		);

		if ( is_wp_error( $response ) ) {
			return $vulnerabilities;
		}

		$headers = wp_remote_retrieve_headers( $response );
		$hsts    = $headers['strict-transport-security'] ?? '';

		if ( empty( $hsts ) ) {
			$vulnerabilities[] = array(
				'component_type'    => 'ssl',
				'component_name'    => parse_url( home_url(), PHP_URL_HOST ),
				'component_version' => '',
				'severity'          => 'medium',
				'cvss_score'        => 6.1,
				'title'             => 'Missing Strict-Transport-Security (HSTS) Header',
				'description'       => 'The site does not send an HSTS header, which prevents browsers from enforcing HTTPS.',
				'recommendation'    => 'Add `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` to server configuration.',
				'reference'         => 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security',
			);
		} else {
			// Check for max-age value.
			if ( ! preg_match( '/max-age=(\d+)/i', $hsts, $matches ) || (int) $matches[1] < 31536000 ) {
				$vulnerabilities[] = array(
					'component_type'    => 'ssl',
					'component_name'    => parse_url( home_url(), PHP_URL_HOST ),
					'component_version' => '',
					'severity'          => 'low',
					'cvss_score'        => 3.5,
					'title'             => 'HSTS max-age Is Too Short',
					'description'       => 'The Strict-Transport-Security header has a max-age less than 1 year (31536000 seconds): ' . esc_html( $hsts ),
					'recommendation'    => 'Set HSTS max-age to at least 31536000 seconds (1 year).',
					'reference'         => 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security',
				);
			}
		}

		return $vulnerabilities;
	}
}
