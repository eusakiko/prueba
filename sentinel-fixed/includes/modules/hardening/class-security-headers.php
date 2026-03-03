<?php
/**
 * HTTP Security Headers Manager.
 *
 * Manages and emits all security-relevant HTTP response headers:
 *
 *  • Content-Security-Policy (report-only or enforce)
 *  • Cross-Origin Resource Sharing (CORS)
 *  • HTTP Strict Transport Security (HSTS)
 *  • X-Frame-Options
 *  • X-Content-Type-Options
 *  • Referrer-Policy
 *  • Permissions-Policy
 *
 * Inspired by Sucuri's SucuriScanCSPHeaders / SucuriScanCORSHeaders classes,
 * adapted to the Sentinel architecture and extended with the remaining headers.
 *
 * Settings are stored under the 'sentinel_headers' wp_option key and are managed
 * through the admin "Headers" page (admin/views/headers.php).
 *
 * @package WP_Sentinel_Security
 * @since   2.8.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Sentinel_Security_Headers
 */
class Sentinel_Security_Headers {

	// ── Option key ────────────────────────────────────────────────────────────

	const OPTION_KEY = 'sentinel_headers';

	// ── Default config structure ──────────────────────────────────────────────

	/**
	 * Returns the default header configuration.
	 *
	 * @return array<string,mixed>
	 */
	public static function defaults() {
		return array(
			// ── Simple on/off headers ──────────────────────────────────────────
			'x_content_type_options' => true,     // Always "nosniff"
			'x_frame_options'        => 'SAMEORIGIN', // DENY | SAMEORIGIN | disabled
			'referrer_policy'        => 'strict-origin-when-cross-origin',

			// ── HSTS ───────────────────────────────────────────────────────────
			'hsts_enabled'           => false,
			'hsts_max_age'           => 31536000, // 1 year
			'hsts_include_subdomains'=> true,
			'hsts_preload'           => false,

			// ── Permissions-Policy ────────────────────────────────────────────
			'permissions_policy'     => array(
				'camera'         => 'none',   // none | self | * | (origin list)
				'microphone'     => 'none',
				'geolocation'    => 'none',
				'payment'        => 'self',
				'usb'            => 'none',
				'fullscreen'     => 'self',
				'accelerometer'  => 'none',
				'gyroscope'      => 'none',
				'magnetometer'   => 'none',
				'display-capture'=> 'none',
			),

			// ── CSP ────────────────────────────────────────────────────────────
			'csp_enabled'  => false,         // false | report-only | enforce
			'csp_directives' => array(
				'default-src'  => array( 'enabled' => false, 'value' => "'self'" ),
				'script-src'   => array( 'enabled' => false, 'value' => "'self'" ),
				'style-src'    => array( 'enabled' => false, 'value' => "'self' 'unsafe-inline'" ),
				'img-src'      => array( 'enabled' => false, 'value' => "'self' data:" ),
				'font-src'     => array( 'enabled' => false, 'value' => "'self'" ),
				'connect-src'  => array( 'enabled' => false, 'value' => "'self'" ),
				'frame-src'    => array( 'enabled' => false, 'value' => "'none'" ),
				'object-src'   => array( 'enabled' => false, 'value' => "'none'" ),
				'base-uri'     => array( 'enabled' => false, 'value' => "'self'" ),
				'form-action'  => array( 'enabled' => false, 'value' => "'self'" ),
				'frame-ancestors' => array( 'enabled' => false, 'value' => "'self'" ),
				'upgrade-insecure-requests' => array( 'enabled' => false, 'value' => '' ),
				'report-uri'   => array( 'enabled' => false, 'value' => '' ),
			),

			// ── CORS ───────────────────────────────────────────────────────────
			'cors_enabled'  => false,
			'cors_options'  => array(
				'allow_origin'      => array( 'enabled' => false, 'value' => '*' ),
				'allow_methods'     => array( 'enabled' => false, 'value' => 'GET, POST, OPTIONS' ),
				'allow_headers'     => array( 'enabled' => false, 'value' => 'Content-Type, Authorization' ),
				'allow_credentials' => array( 'enabled' => false, 'value' => 'false' ),
				'expose_headers'    => array( 'enabled' => false, 'value' => '' ),
				'max_age'           => array( 'enabled' => false, 'value' => '3600' ),
			),
		);
	}

	// ── Public API ─────────────────────────────────────────────────────────────

	/**
	 * Retrieve the current saved configuration, merged with defaults.
	 *
	 * @return array
	 */
	public static function get_config() {
		$saved = get_option( self::OPTION_KEY, array() );
		return self::deep_merge( self::defaults(), is_array( $saved ) ? $saved : array() );
	}

	/**
	 * Persist a new configuration.
	 *
	 * @param array $config Raw admin form data (will be sanitized internally).
	 * @return bool
	 */
	public static function save_config( $config ) {
		return update_option( self::OPTION_KEY, self::sanitize( $config ) );
	}

	/**
	 * Emit all enabled security headers.
	 * Must be called before any output (hook: 'send_headers' or 'init' with high priority).
	 *
	 * @return void
	 */
	public static function send() {
		if ( headers_sent() ) {
			return;
		}

		$cfg = self::get_config();

		self::send_simple_headers( $cfg );
		self::send_hsts( $cfg );
		self::send_permissions_policy( $cfg );
		self::send_csp( $cfg );
		self::send_cors( $cfg );
	}

	// ── Simple headers ────────────────────────────────────────────────────────

	private static function send_simple_headers( $cfg ) {
		// X-Content-Type-Options.
		if ( ! empty( $cfg['x_content_type_options'] ) ) {
			header( 'X-Content-Type-Options: nosniff' );
		}

		// X-Frame-Options.
		$xfo = $cfg['x_frame_options'] ?? 'SAMEORIGIN';
		if ( 'disabled' !== $xfo && in_array( $xfo, array( 'DENY', 'SAMEORIGIN' ), true ) ) {
			header( 'X-Frame-Options: ' . $xfo );
		}

		// Referrer-Policy.
		$allowed_rp = array(
			'no-referrer', 'no-referrer-when-downgrade', 'origin',
			'origin-when-cross-origin', 'same-origin', 'strict-origin',
			'strict-origin-when-cross-origin', 'unsafe-url',
		);
		$rp = $cfg['referrer_policy'] ?? 'strict-origin-when-cross-origin';
		if ( in_array( $rp, $allowed_rp, true ) ) {
			header( 'Referrer-Policy: ' . $rp );
		}
	}

	// ── HSTS ─────────────────────────────────────────────────────────────────

	private static function send_hsts( $cfg ) {
		if ( empty( $cfg['hsts_enabled'] ) ) {
			return;
		}

		// Only send over HTTPS.
		if ( ! is_ssl() ) {
			return;
		}

		$max_age = max( 0, (int) ( $cfg['hsts_max_age'] ?? 31536000 ) );
		$value   = 'max-age=' . $max_age;

		if ( ! empty( $cfg['hsts_include_subdomains'] ) ) {
			$value .= '; includeSubDomains';
		}

		if ( ! empty( $cfg['hsts_preload'] ) ) {
			$value .= '; preload';
		}

		header( 'Strict-Transport-Security: ' . $value );
	}

	// ── Permissions-Policy ───────────────────────────────────────────────────

	/**
	 * Allowed Permissions-Policy feature names (partial list of standardized features).
	 *
	 * @var string[]
	 */
	private static $pp_features = array(
		'accelerometer', 'ambient-light-sensor', 'autoplay', 'battery', 'camera',
		'cross-origin-isolated', 'display-capture', 'document-domain',
		'encrypted-media', 'execution-while-not-rendered',
		'execution-while-out-of-viewport', 'fullscreen', 'geolocation',
		'gyroscope', 'keyboard-map', 'magnetometer', 'microphone', 'midi',
		'navigation-override', 'payment', 'picture-in-picture',
		'publickey-credentials-get', 'screen-wake-lock', 'sync-xhr',
		'usb', 'web-share', 'xr-spatial-tracking',
	);

	private static function send_permissions_policy( $cfg ) {
		$pp = $cfg['permissions_policy'] ?? array();
		if ( empty( $pp ) ) {
			return;
		}

		$directives = array();
		foreach ( $pp as $feature => $allow ) {
			// Normalize feature name (underscores → hyphens).
			$feature = str_replace( '_', '-', sanitize_key( $feature ) );
			if ( ! in_array( $feature, self::$pp_features, true ) ) {
				continue;
			}

			$allow = trim( (string) $allow );
			if ( 'none' === $allow || '' === $allow ) {
				$directives[] = $feature . '=()';
			} elseif ( 'self' === $allow ) {
				$directives[] = $feature . '=(self)';
			} elseif ( '*' === $allow ) {
				$directives[] = $feature . '=*';
			} else {
				// Treat as space-separated origin list.
				$origins = array_filter( array_map( 'trim', explode( ' ', $allow ) ) );
				$cleaned = array();
				foreach ( $origins as $o ) {
					if ( preg_match( '#^https?://#', $o ) ) {
						$cleaned[] = '"' . esc_url_raw( $o ) . '"';
					}
				}
				if ( $cleaned ) {
					$directives[] = $feature . '=(' . implode( ' ', $cleaned ) . ')';
				}
			}
		}

		if ( $directives ) {
			header( 'Permissions-Policy: ' . implode( ', ', $directives ) );
		}
	}

	// ── CSP ───────────────────────────────────────────────────────────────────

	/** CSP directives that accept a source list. */
	private static $csp_source_directives = array(
		'default-src', 'script-src', 'style-src', 'img-src', 'font-src',
		'connect-src', 'frame-src', 'object-src', 'base-uri', 'form-action',
		'frame-ancestors', 'media-src', 'worker-src', 'manifest-src',
		'child-src', 'prefetch-src',
	);

	/** CSP keywords that are always allowed. */
	private static $csp_keywords = array(
		"'self'", "'none'", "'unsafe-inline'", "'unsafe-eval'",
		"'strict-dynamic'", "'unsafe-hashes'", "'report-sample'",
	);

	private static function send_csp( $cfg ) {
		$mode = $cfg['csp_enabled'] ?? false;
		if ( ! $mode || 'disabled' === $mode ) {
			return;
		}

		$parts = array();

		foreach ( (array) ( $cfg['csp_directives'] ?? array() ) as $directive => $opt ) {
			if ( empty( $opt['enabled'] ) ) {
				continue;
			}

			$value = trim( (string) ( $opt['value'] ?? '' ) );

			// Bare directives (no value).
			if ( 'upgrade-insecure-requests' === $directive ) {
				$parts[] = 'upgrade-insecure-requests';
				continue;
			}

			// report-uri / report-to: must be a URL.
			if ( in_array( $directive, array( 'report-uri', 'report-to' ), true ) ) {
				if ( filter_var( $value, FILTER_VALIDATE_URL ) ) {
					$parts[] = $directive . ' ' . esc_url_raw( $value );
				}
				continue;
			}

			if ( in_array( $directive, self::$csp_source_directives, true ) ) {
				$sanitized = self::sanitize_csp_source_list( $value );
				if ( $sanitized ) {
					$parts[] = $directive . ' ' . $sanitized;
				}
				continue;
			}
		}

		if ( ! $parts ) {
			return;
		}

		$header_value = implode( '; ', $parts );

		if ( 'report-only' === $mode ) {
			header( 'Content-Security-Policy-Report-Only: ' . $header_value );
		} else {
			header( 'Content-Security-Policy: ' . $header_value );
		}
	}

	/**
	 * Sanitize a CSP source list string.
	 *
	 * @param string $value Raw source list (e.g. "'self' https://cdn.example.com").
	 * @return string Sanitized list or empty string.
	 */
	private static function sanitize_csp_source_list( $value ) {
		$tokens   = preg_split( '/\s+/', trim( $value ), -1, PREG_SPLIT_NO_EMPTY );
		$accepted = array();

		foreach ( $tokens as $token ) {
			// CSP keywords ('self', 'none', etc.).
			if ( in_array( $token, self::$csp_keywords, true ) ) {
				$accepted[] = $token;
				continue;
			}

			// Wildcard.
			if ( '*' === $token ) {
				$accepted[] = '*';
				continue;
			}

			// Scheme: data: blob: https: etc.
			if ( preg_match( '#^(https?:|data:|blob:|filesystem:|mediastream:)$#i', $token ) ) {
				$accepted[] = $token;
				continue;
			}

			// Nonce or hash: 'nonce-...' 'sha256-...'
			if ( preg_match( "/^'(nonce-[A-Za-z0-9+\\/=]+|sha(?:256|384|512)-[A-Za-z0-9+\\/=]+)'$/", $token ) ) {
				$accepted[] = $token;
				continue;
			}

			// Host sources: https://example.com, *.example.com, example.com:8080, etc.
			if ( preg_match( '#^(https?://)?(\*\.)?[a-zA-Z0-9\-]+((\.[a-zA-Z0-9\-]+)*)(?::[0-9]+)?(/.*)?$#', $token ) ) {
				$accepted[] = $token;
				continue;
			}
		}

		return implode( ' ', $accepted );
	}

	// ── CORS ──────────────────────────────────────────────────────────────────

	private static function send_cors( $cfg ) {
		if ( empty( $cfg['cors_enabled'] ) ) {
			return;
		}

		$opts = $cfg['cors_options'] ?? array();

		// Access-Control-Allow-Origin.
		if ( ! empty( $opts['allow_origin']['enabled'] ) ) {
			$origin = sanitize_text_field( $opts['allow_origin']['value'] ?? '' );
			if ( $origin ) {
				header( 'Access-Control-Allow-Origin: ' . $origin );
			}
		}

		// Access-Control-Allow-Methods.
		if ( ! empty( $opts['allow_methods']['enabled'] ) ) {
			$methods = self::sanitize_methods( $opts['allow_methods']['value'] ?? '' );
			if ( $methods ) {
				header( 'Access-Control-Allow-Methods: ' . $methods );
			}
		}

		// Access-Control-Allow-Headers.
		if ( ! empty( $opts['allow_headers']['enabled'] ) ) {
			$hdrs = self::sanitize_header_list( $opts['allow_headers']['value'] ?? '' );
			if ( $hdrs ) {
				header( 'Access-Control-Allow-Headers: ' . $hdrs );
			}
		}

		// Access-Control-Allow-Credentials.
		if ( ! empty( $opts['allow_credentials']['enabled'] )
			&& 'true' === ( $opts['allow_credentials']['value'] ?? '' ) ) {
			header( 'Access-Control-Allow-Credentials: true' );
		}

		// Access-Control-Expose-Headers.
		if ( ! empty( $opts['expose_headers']['enabled'] ) ) {
			$exp = self::sanitize_header_list( $opts['expose_headers']['value'] ?? '' );
			if ( $exp ) {
				header( 'Access-Control-Expose-Headers: ' . $exp );
			}
		}

		// Access-Control-Max-Age.
		if ( ! empty( $opts['max_age']['enabled'] ) ) {
			$age = (int) preg_replace( '/\D/', '', (string) ( $opts['max_age']['value'] ?? '' ) );
			if ( $age > 0 ) {
				header( 'Access-Control-Max-Age: ' . $age );
			}
		}
	}

	private static function sanitize_methods( $value ) {
		$allowed = array( 'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD' );
		$tokens  = preg_split( '/[\s,]+/', strtoupper( trim( $value ) ), -1, PREG_SPLIT_NO_EMPTY );
		$clean   = array_filter( $tokens, function ( $t ) use ( $allowed ) {
			return in_array( $t, $allowed, true );
		} );
		return implode( ', ', $clean );
	}

	private static function sanitize_header_list( $value ) {
		$tokens = preg_split( '/\s*,\s*/', trim( $value ), -1, PREG_SPLIT_NO_EMPTY );
		$clean  = array();
		foreach ( $tokens as $t ) {
			// RFC 7230 token characters.
			$t = preg_replace( "/[^!#\$%&'*+\-.^_`|~0-9A-Za-z]/", '', $t );
			if ( $t ) {
				$clean[] = $t;
			}
		}
		return implode( ', ', $clean );
	}

	// ── Sanitization ─────────────────────────────────────────────────────────

	/**
	 * Sanitize raw admin form input before saving.
	 *
	 * @param array $raw Raw POST data.
	 * @return array
	 */
	public static function sanitize( $raw ) {
		$defaults = self::defaults();
		$out      = array();

		// Simple booleans.
		$out['x_content_type_options'] = ! empty( $raw['x_content_type_options'] );
		$out['hsts_enabled']           = ! empty( $raw['hsts_enabled'] );
		$out['hsts_include_subdomains']= ! empty( $raw['hsts_include_subdomains'] );
		$out['hsts_preload']           = ! empty( $raw['hsts_preload'] );
		$out['cors_enabled']           = ! empty( $raw['cors_enabled'] );

		// HSTS max-age.
		$out['hsts_max_age'] = max( 0, (int) ( $raw['hsts_max_age'] ?? 31536000 ) );

		// X-Frame-Options.
		$xfo_values       = array( 'DENY', 'SAMEORIGIN', 'disabled' );
		$out['x_frame_options'] = in_array( $raw['x_frame_options'] ?? '', $xfo_values, true )
			? $raw['x_frame_options']
			: 'SAMEORIGIN';

		// Referrer-Policy.
		$allowed_rp = array(
			'no-referrer', 'no-referrer-when-downgrade', 'origin',
			'origin-when-cross-origin', 'same-origin', 'strict-origin',
			'strict-origin-when-cross-origin', 'unsafe-url',
		);
		$out['referrer_policy'] = in_array( $raw['referrer_policy'] ?? '', $allowed_rp, true )
			? $raw['referrer_policy']
			: 'strict-origin-when-cross-origin';

		// Permissions-Policy.
		$pp_values = array( 'none', 'self', '*' );
		$out['permissions_policy'] = array();
		foreach ( $defaults['permissions_policy'] as $feature => $default ) {
			$v = sanitize_text_field( $raw['permissions_policy'][ $feature ] ?? $default );
			$out['permissions_policy'][ $feature ] = in_array( $v, $pp_values, true ) ? $v : 'none';
		}

		// CSP.
		$csp_modes           = array( false, 'disabled', 'report-only', 'enforce' );
		$raw_csp_mode        = $raw['csp_enabled'] ?? false;
		$out['csp_enabled']  = in_array( $raw_csp_mode, $csp_modes, true ) ? $raw_csp_mode : false;

		$out['csp_directives'] = array();
		foreach ( $defaults['csp_directives'] as $directive => $default ) {
			$dir_data = $raw['csp_directives'][ $directive ] ?? array();
			$out['csp_directives'][ $directive ] = array(
				'enabled' => ! empty( $dir_data['enabled'] ),
				'value'   => sanitize_text_field( $dir_data['value'] ?? $default['value'] ),
			);
		}

		// CORS options.
		$out['cors_options'] = array();
		foreach ( $defaults['cors_options'] as $key => $default ) {
			$cor_data = $raw['cors_options'][ $key ] ?? array();
			$out['cors_options'][ $key ] = array(
				'enabled' => ! empty( $cor_data['enabled'] ),
				'value'   => sanitize_text_field( $cor_data['value'] ?? $default['value'] ),
			);
		}

		return $out;
	}

	// ── Helpers ───────────────────────────────────────────────────────────────

	/**
	 * Deep-merge two arrays (second wins).
	 *
	 * @param array $base
	 * @param array $override
	 * @return array
	 */
	private static function deep_merge( $base, $override ) {
		foreach ( $override as $key => $value ) {
			if ( is_array( $value ) && isset( $base[ $key ] ) && is_array( $base[ $key ] ) ) {
				$base[ $key ] = self::deep_merge( $base[ $key ], $value );
			} else {
				$base[ $key ] = $value;
			}
		}
		return $base;
	}
}
