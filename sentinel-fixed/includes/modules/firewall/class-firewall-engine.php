<?php
/**
 * Web Application Firewall (WAF) engine.
 *
 * Inspects incoming HTTP requests for common attack patterns
 * (SQL injection, XSS, LFI/RFI, command injection, protocol attacks)
 * and blocks them before WordPress processes the request.
 *
 * @package WP_Sentinel_Security
 * @since   2.1.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Firewall_Engine
 */
class Firewall_Engine {

	/**
	 * Plugin settings.
	 *
	 * @var array
	 */
	private $settings;

	/**
	 * IP Manager instance.
	 *
	 * @var IP_Manager|null
	 */
	private $ip_manager;

	/**
	 * WAF rule definitions.
	 *
	 * Each rule: [ 'id' => string, 'pattern' => regex, 'description' => string, 'severity' => string ]
	 *
	 * @var array
	 */
	private static $rules = array(
		// SQL Injection patterns.
		array(
			'id'          => 'sqli-union',
			'pattern'     => '/(?:union\s+(?:all\s+)?select)/i',
			'description' => 'SQL injection: UNION SELECT',
			'severity'    => 'critical',
		),
		array(
			'id'          => 'sqli-comment',
			// Refined pattern: require preceding non-HTML-comment context.
			// '<!--' is legitimate HTML; only bare '--' or '#' at EOL after
			// a non-'<' character are SQL comment terminators.
			'pattern'     => '/(?<![<\s])--\s*$|(?:^|[^a-zA-Z])#\s*$|\/\*[^!]/m',
			'description' => 'SQL injection: comment terminator',
			'severity'    => 'high',
		),
		array(
			'id'          => 'sqli-tautology',
			// Require a SQL-context indicator before the tautology: closing quote,
			// closing paren, or a digit/word-boundary typical of injected payloads.
			// This reduces false positives from natural-language text like
			// "there are 1=1 ways" while still catching ' OR 1=1 and 1 OR 1=1--.
			// Note: bare leading-edge cases (e.g. "OR 1=1" at start of input)
			// are intentionally excluded to avoid false positives; stacked-query
			// and union rules cover those attack vectors instead.
			'pattern'     => '/[\'"\)]\s*(?:\bor\b|\band\b)\s+\d+\s*=\s*\d+/i',
			'description' => 'SQL injection: tautology (e.g. OR 1=1)',
			'severity'    => 'critical',
		),
		array(
			'id'          => 'sqli-sleep',
			'pattern'     => '/(?:sleep\s*\(\s*\d+\s*\)|benchmark\s*\()/i',
			'description' => 'SQL injection: time-based blind (SLEEP/BENCHMARK)',
			'severity'    => 'critical',
		),
		array(
			'id'          => 'sqli-stacked',
			'pattern'     => '/;\s*(?:drop|alter|truncate|insert|update|delete)\s/i',
			'description' => 'SQL injection: stacked query',
			'severity'    => 'critical',
		),
		// XSS patterns.
		array(
			'id'          => 'xss-script-tag',
			'pattern'     => '/<\s*script[^>]*>/i',
			'description' => 'XSS: script tag injection',
			'severity'    => 'high',
		),
		array(
			'id'          => 'xss-event-handler',
			'pattern'     => '/\bon(?:error|load|click|mouse|focus|blur|submit|change|key)\s*=/i',
			'description' => 'XSS: inline event handler injection',
			'severity'    => 'high',
		),
		array(
			'id'          => 'xss-javascript-uri',
			'pattern'     => '/javascript\s*:/i',
			'description' => 'XSS: javascript: URI scheme',
			'severity'    => 'high',
		),
		// Local/Remote File Inclusion.
		array(
			'id'          => 'lfi-traversal',
			'pattern'     => '/(?:\.\.\/){2,}/',
			'description' => 'LFI: directory traversal',
			'severity'    => 'critical',
		),
		array(
			'id'          => 'lfi-etc-passwd',
			'pattern'     => '/\/etc\/(?:passwd|shadow|hosts)/i',
			'description' => 'LFI: access to sensitive system files',
			'severity'    => 'critical',
		),
		array(
			'id'          => 'rfi-remote-include',
			'pattern'     => '/(?:include|require)(?:_once)?\s*\(\s*[\'"]https?:\/\//i',
			'description' => 'RFI: remote file inclusion via URL',
			'severity'    => 'critical',
		),
		// Command injection.
		array(
			'id'          => 'cmdi-pipe',
			'pattern'     => '/(?:\||;)\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|bash|sh)\b/i',
			'description' => 'Command injection: piped shell command',
			'severity'    => 'critical',
		),
		array(
			'id'          => 'cmdi-backtick',
			'pattern'     => '/`[^`]*(?:cat|ls|id|whoami|wget|curl)\b[^`]*`/i',
			'description' => 'Command injection: backtick execution',
			'severity'    => 'critical',
		),
		// Protocol attacks.
		array(
			'id'          => 'proto-null-byte',
			'pattern'     => '/(?:%00|\x00)/',
			'description' => 'Null byte injection',
			'severity'    => 'high',
		),
		array(
			'id'          => 'proto-php-wrapper',
			'pattern'     => '/php:\/\/(?:input|filter|data)/i',
			'description' => 'PHP stream wrapper abuse',
			'severity'    => 'critical',
		),
		// SSRF: requests targeting internal/loopback addresses.
		array(
			'id'          => 'ssrf-internal',
			'pattern'     => '/(?:https?|ftp):\/\/(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|::1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)/i',
			'description' => 'SSRF: request targeting internal/loopback address',
			'severity'    => 'critical',
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
	 * Initialize the firewall: load IP manager and register early hook.
	 *
	 * @return void
	 */
	public function init() {
		$base = SENTINEL_PLUGIN_DIR . 'includes/modules/firewall/';
		require_once $base . 'class-ip-manager.php';

		$this->ip_manager = new IP_Manager( $this->settings );

		if ( $this->is_enabled() ) {
			add_action( 'init', array( $this, 'inspect_request' ), 1 );

			// Rate limiter — always load alongside WAF.
			require_once $base . 'class-rate-limiter.php';
			( new Rate_Limiter( $this->settings ) )->init();
		}
	}

	/**
	 * Whether the WAF is enabled in settings.
	 *
	 * @return bool
	 */
	public function is_enabled() {
		return ! empty( $this->settings['waf_enabled'] );
	}

	/**
	 * Inspect the current request against all WAF rules.
	 *
	 * Collects input from GET, POST, cookies, URI, and User-Agent,
	 * then runs each value through the rule set.
	 *
	 * @return void
	 */
	public function inspect_request() {
		// Skip inspection for whitelisted IPs.
		$client_ip = $this->get_client_ip();
		if ( $this->ip_manager && $this->ip_manager->is_whitelisted( $client_ip ) ) {
			return;
		}

		// Check if IP is blocked — log the event before terminating the request.
		if ( $this->ip_manager && $this->ip_manager->is_blocked( $client_ip ) ) {
			$ip_rule = array(
				'id'          => 'ip_blocked',
				'description' => 'IP address is in the blocked list.',
				'severity'    => 'high',
			);
			$this->log_blocked_request( $ip_rule, $client_ip, $client_ip );
			$this->block_request( 'ip_blocked', 'Your IP address has been blocked.', $client_ip );
		}

		$inputs = $this->collect_inputs();

		foreach ( $inputs as $input ) {
			$match = $this->match_rules( $input );
			if ( null !== $match ) {
				$this->log_blocked_request( $match, $client_ip, $input );
				$this->block_request( $match['id'], $match['description'], $client_ip );
			}
		}
	}

	/**
	 * Match a single input string against all WAF rules (built-in + custom).
	 *
	 * @param string $input Input string to test.
	 * @return array|null Matched rule array or null.
	 */
	public function match_rules( $input ) {
		if ( ! is_string( $input ) || '' === $input ) {
			return null;
		}

		// Decode common encoding layers before matching.
		$decoded = $this->decode_input( $input );

		// Merge built-in rules with admin-defined custom rules.
		$all_rules = self::$rules;
		$custom    = (array) ( $this->settings['waf_custom_rules'] ?? array() );
		foreach ( $custom as $rule ) {
			if ( ! empty( $rule['id'] ) && ! empty( $rule['pattern'] ) ) {
				$all_rules[] = array(
					'id'          => $rule['id'],
					'pattern'     => $rule['pattern'],
					'description' => $rule['description'] ?? 'Custom WAF rule',
					'severity'    => $rule['severity']    ?? 'medium',
				);
			}
		}

		foreach ( $all_rules as $rule ) {
			// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			if ( @preg_match( $rule['pattern'], $decoded ) ) {
				return $rule;
			}
		}

		return null;
	}

	/**
	 * Get all registered WAF rules.
	 *
	 * @return array
	 */
	public static function get_rules() {
		return self::$rules;
	}

	/**
	 * Get the IP Manager instance.
	 *
	 * @return IP_Manager|null
	 */
	public function get_ip_manager() {
		return $this->ip_manager;
	}

	// -------------------------------------------------------------------------
	// Private helpers
	// -------------------------------------------------------------------------

	/**
	 * Collect all relevant input values from the current request.
	 *
	 * @return string[] Flat array of input strings to inspect.
	 */
	private function collect_inputs() {
		$inputs = array();

		/*
		 * IMPORTANT: Do NOT sanitize server values before WAF inspection.
		 * sanitize_text_field() strips HTML tags via wp_strip_all_tags(),
		 * which would remove patterns like <script> BEFORE the XSS rules
		 * can detect them — creating a trivial WAF bypass.
		 * Raw (unslashed) values are used here intentionally.
		 */

		// Request URI — raw, unslashed.
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		if ( ! empty( $_SERVER['REQUEST_URI'] ) ) {
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			$inputs[] = wp_unslash( $_SERVER['REQUEST_URI'] );
		}

		// Query string — raw, unslashed.
		if ( ! empty( $_SERVER['QUERY_STRING'] ) ) {
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			$inputs[] = wp_unslash( $_SERVER['QUERY_STRING'] );
		}

		// User agent — raw, unslashed.
		if ( ! empty( $_SERVER['HTTP_USER_AGENT'] ) ) {
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			$inputs[] = wp_unslash( $_SERVER['HTTP_USER_AGENT'] );
		}

		// GET parameters — raw values inspected intentionally (sanitization would strip attack patterns).
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$inputs = array_merge( $inputs, $this->flatten_input( $_GET ) );

		// POST parameters — raw values inspected intentionally for WAF pattern detection.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$inputs = array_merge( $inputs, $this->flatten_input( $_POST ) );

		// Cookie values — raw values inspected intentionally for WAF pattern detection.
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$inputs = array_merge( $inputs, $this->flatten_input( $_COOKIE ) );

		return $inputs;
	}

	/**
	 * Recursively flatten a superglobal array into a flat list of string values.
	 *
	 * Handles nested arrays such as $_POST['data']['sql'] = 'payload'.
	 *
	 * @param array $data   Input array (may be nested).
	 * @param int   $depth  Current recursion depth (max 5 to avoid DoS).
	 * @return string[] Flat list of unslashed string values.
	 */
	private function flatten_input( $data, $depth = 0 ) {
		$strings = array();
		if ( ! is_array( $data ) || $depth > 5 ) {
			return $strings;
		}
		foreach ( $data as $value ) {
			if ( is_string( $value ) ) {
				$strings[] = wp_unslash( $value );
			} elseif ( is_array( $value ) ) {
				$strings = array_merge( $strings, $this->flatten_input( $value, $depth + 1 ) );
			}
		}
		return $strings;
	}

	/**
	 * Decode common encoding layers applied by attackers.
	 *
	 * @param string $input Raw input string.
	 * @return string Decoded string.
	 */
	private function decode_input( $input ) {
		// URL decode (double-decode to catch double-encoding).
		$decoded = rawurldecode( rawurldecode( $input ) );

		// HTML entity decode.
		$decoded = html_entity_decode( $decoded, ENT_QUOTES, 'UTF-8' );

		return $decoded;
	}

	/**
	 * Log a blocked request to the activity log.
	 *
	 * @param array  $rule      Matched WAF rule.
	 * @param string $client_ip Client IP address.
	 * @param string $input     The input that triggered the rule.
	 * @return void
	 */
	private function log_blocked_request( $rule, $client_ip, $input ) {
		global $wpdb;

		if ( ! isset( $wpdb ) || ! $wpdb ) {
			return;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$wpdb->insert(
			"{$wpdb->prefix}sentinel_activity_log",
			array(
				'user_id'        => function_exists( 'get_current_user_id' ) ? get_current_user_id() : 0,
				'event_type'     => 'waf_blocked',
				'event_category' => 'firewall',
				'severity'       => sanitize_text_field( $rule['severity'] ),
				'description'    => sanitize_text_field( $rule['description'] ),
				'ip_address'     => sanitize_text_field( $client_ip ),
				'user_agent'     => isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '',
				'object_type'    => 'waf_rule',
				'object_id'      => sanitize_text_field( $rule['id'] ),
				'metadata'       => wp_json_encode( array( 'matched_input' => substr( $input, 0, 500 ) ) ),
				'created_at'     => current_time( 'mysql' ),
			),
			array( '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s' )
		);
	}

	/**
	 * Block the request with a 403 Forbidden response and exit.
	 *
	 * @param string $rule_id    ID of the triggered WAF rule.
	 * @param string $reason     Human-readable reason.
	 * @param string $client_ip  Client IP address.
	 * @return void
	 */
	private function block_request( $rule_id, $reason, $client_ip ) {
		status_header( 403 );
		nocache_headers();
		// Harden the blocked-response page against content sniffing and clickjacking.
		header( 'X-Content-Type-Options: nosniff' );
		header( 'X-Frame-Options: DENY' );

		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			wp_die(
				esc_html( $reason ),
				esc_html__( 'Blocked by WP Sentinel Firewall', 'wp-sentinel-security' ),
				array( 'response' => 403 )
			);
		} else {
			wp_die(
				esc_html__( 'Access denied.', 'wp-sentinel-security' ),
				esc_html__( 'Blocked by WP Sentinel Firewall', 'wp-sentinel-security' ),
				array( 'response' => 403 )
			);
		}
	}

	/**
	 * Get the client IP address.
	 *
	 * @return string
	 */
	private function get_client_ip() {
		if ( class_exists( 'Sentinel_Helper' ) && method_exists( 'Sentinel_Helper', 'get_client_ip' ) ) {
			return Sentinel_Helper::get_client_ip();
		}

		if ( ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
			return sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
		}

		return '0.0.0.0';
	}
}
