<?php
/**
 * HTTP Security Headers Analyzer.
 *
 * Fetches the site's home URL and evaluates the presence and configuration
 * of critical HTTP security headers, producing scored findings.
 *
 * @package WP_Sentinel_Security
 * @since   2.2.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Header_Analyzer
 */
class Header_Analyzer {

	/**
	 * Plugin settings.
	 *
	 * @var array
	 */
	private $settings;

	/**
	 * Headers that should be present and their check definitions.
	 *
	 * Format: header_name => [ description, recommendation, reference, points, severity ]
	 *
	 * @var array
	 */
	private static $required_headers = array(
		'content-security-policy'   => array(
			'description'    => 'Content-Security-Policy (CSP) header is missing. CSP prevents XSS attacks by controlling which resources the browser is allowed to load.',
			'recommendation' => 'Add a Content-Security-Policy header. Start with default-src \'self\' and refine from there.',
			'reference'      => 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP',
			'points'         => 25,
			'severity'       => 'high',
			'cvss_score'     => 6.1,
		),
		'x-frame-options'           => array(
			'description'    => 'X-Frame-Options header is missing. This allows the site to be embedded in iframes, enabling clickjacking attacks.',
			'recommendation' => 'Add X-Frame-Options: SAMEORIGIN to your server configuration.',
			'reference'      => 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options',
			'points'         => 10,
			'severity'       => 'medium',
			'cvss_score'     => 5.4,
		),
		'x-content-type-options'    => array(
			'description'    => 'X-Content-Type-Options header is missing. Browsers may MIME-sniff responses, leading to unexpected code execution.',
			'recommendation' => 'Add X-Content-Type-Options: nosniff to your server configuration.',
			'reference'      => 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options',
			'points'         => 10,
			'severity'       => 'medium',
			'cvss_score'     => 5.0,
		),
		'referrer-policy'           => array(
			'description'    => 'Referrer-Policy header is missing. The browser may leak the full URL of the referrer page to external sites.',
			'recommendation' => 'Add Referrer-Policy: no-referrer-when-downgrade or strict-origin-when-cross-origin.',
			'reference'      => 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy',
			'points'         => 10,
			'severity'       => 'low',
			'cvss_score'     => 3.7,
		),
		'permissions-policy'        => array(
			'description'    => 'Permissions-Policy header is missing. Browser APIs (camera, microphone, geolocation) may be accessible by scripts.',
			'recommendation' => 'Add a Permissions-Policy header to restrict browser feature access.',
			'reference'      => 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy',
			'points'         => 10,
			'severity'       => 'low',
			'cvss_score'     => 3.5,
		),
		'strict-transport-security' => array(
			'description'    => 'Strict-Transport-Security (HSTS) header is missing. Browsers will not enforce HTTPS for this site.',
			'recommendation' => 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains to your HTTPS server.',
			'reference'      => 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security',
			'points'         => 20,
			'severity'       => 'high',
			'cvss_score'     => 7.0,
		),
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
	 * Run the header analysis scan.
	 *
	 * @return array Array of vulnerability data arrays.
	 */
	public function scan() {
		$vulnerabilities = array();

		$response = wp_remote_get(
			home_url(),
			array(
				'timeout'     => 8,
				'redirection' => 3,
				'sslverify'   => true,
			)
		);

		if ( is_wp_error( $response ) ) {
			return $vulnerabilities;
		}

		$headers = wp_remote_retrieve_headers( $response );

		foreach ( self::$required_headers as $header_name => $config ) {
			$value = $headers[ $header_name ] ?? '';

			if ( empty( $value ) ) {
				$vulnerabilities[] = array(
					'component_type'    => 'headers',
					'component_name'    => 'HTTP Header: ' . strtoupper( str_replace( '-', '_', $header_name ) ),
					'component_version' => '',
					'severity'          => $config['severity'],
					'cvss_score'        => (float) $config['cvss_score'],
					'title'             => 'Missing Security Header: ' . $header_name,
					'description'       => $config['description'],
					'recommendation'    => $config['recommendation'],
					'reference'         => $config['reference'],
				);
			} else {
				// Additional checks for specific headers.
				$extra = $this->check_header_value( $header_name, (string) $value );
				if ( $extra ) {
					$vulnerabilities[] = $extra;
				}
			}
		}

		// Check for X-Powered-By information disclosure.
		$powered_by = $headers['x-powered-by'] ?? '';
		if ( ! empty( $powered_by ) ) {
			$vulnerabilities[] = array(
				'component_type'    => 'headers',
				'component_name'    => 'HTTP Header: X-Powered-By',
				'component_version' => '',
				'severity'          => 'low',
				'cvss_score'        => 3.5,
				'title'             => 'X-Powered-By Header Leaks Technology Information',
				'description'       => 'The X-Powered-By header reveals server technology: ' . esc_html( $powered_by ),
				'recommendation'    => 'Remove the X-Powered-By header from your server configuration.',
				'reference'         => 'https://owasp.org/www-project-secure-headers/',
			);
		}

		return $vulnerabilities;
	}

	/**
	 * Get the header definitions (for external use / reporting).
	 *
	 * @return array
	 */
	public static function get_required_headers() {
		return self::$required_headers;
	}

	/**
	 * Perform additional value checks on specific headers.
	 *
	 * @param string $header_name Header name (lowercase).
	 * @param string $value       Header value.
	 * @return array|null Finding array or null if OK.
	 */
	private function check_header_value( $header_name, $value ) {
		switch ( $header_name ) {
			case 'strict-transport-security':
				if ( ! preg_match( '/max-age=(\d+)/i', $value, $m ) || (int) $m[1] < 31536000 ) {
					return array(
						'component_type'    => 'headers',
						'component_name'    => 'HTTP Header: STRICT_TRANSPORT_SECURITY',
						'component_version' => '',
						'severity'          => 'low',
						'cvss_score'        => 3.5,
						'title'             => 'Weak HSTS max-age Configuration',
						'description'       => 'HSTS max-age is less than 1 year: ' . esc_html( $value ),
						'recommendation'    => 'Set HSTS max-age to at least 31536000 (1 year).',
						'reference'         => 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security',
					);
				}
				break;

			case 'x-frame-options':
				if ( ! in_array( strtoupper( $value ), array( 'DENY', 'SAMEORIGIN' ), true ) ) {
					return array(
						'component_type'    => 'headers',
						'component_name'    => 'HTTP Header: X_FRAME_OPTIONS',
						'component_version' => '',
						'severity'          => 'low',
						'cvss_score'        => 3.5,
						'title'             => 'Weak X-Frame-Options Configuration',
						'description'       => 'X-Frame-Options is set to "' . esc_html( $value ) . '" — use DENY or SAMEORIGIN.',
						'recommendation'    => 'Change X-Frame-Options to DENY or SAMEORIGIN.',
						'reference'         => 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options',
					);
				}
				break;
		}

		return null;
	}
}
