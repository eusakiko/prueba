<?php
/**
 * Rate Limiter — sliding-window per-IP request throttle.
 *
 * Counts requests per IP in a configurable time window using WordPress
 * transients (no extra tables needed). When the threshold is exceeded the
 * request is immediately terminated with a 429 response and the event is
 * logged to the activity log.
 *
 * Configuration is read from sentinel_settings:
 *   rate_limit_enabled   bool   Master switch (default false).
 *   rate_limit_requests  int    Max requests per window (default 120).
 *   rate_limit_window    int    Window size in seconds (default 60).
 *   rate_limit_whitelist array  Paths that are never throttled (default []).
 *
 * @package WP_Sentinel_Security
 * @since   2.5.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Rate_Limiter {

	/** @var array */
	private $settings;

	public function __construct( $settings = array() ) {
		$this->settings = $settings;
	}

	/**
	 * Register hooks. Called by Firewall_Engine::init() when WAF is active.
	 */
	public function init() {
		if ( empty( $this->settings['rate_limit_enabled'] ) ) {
			return;
		}
		// Run as early as possible — before any WP processing.
		add_action( 'init', array( $this, 'check_rate_limit' ), 2 ); // Priority 2: after WAF (1) so attack patterns are logged before 429 termination.
	}

	/**
	 * Check the current request against the rate limit.
	 * Terminates with 429 if the limit is exceeded.
	 */
	public function check_rate_limit() {
		// Never throttle WP-CLI or cron.
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return;
		}
		if ( defined( 'DOING_CRON' ) && DOING_CRON ) {
			return;
		}

		// Skip whitelisted paths.
		$whitelist    = (array) ( $this->settings['rate_limit_whitelist'] ?? array() );
		$request_uri  = isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : '/';
		$request_path = strtok( $request_uri, '?' );

		foreach ( $whitelist as $allowed ) {
			if ( $allowed && 0 === strpos( $request_path, $allowed ) ) {
				return;
			}
		}

		$ip      = $this->get_client_ip();
		$window  = max( 1, (int) ( $this->settings['rate_limit_window']   ?? 60  ) );
		$limit   = max( 1, (int) ( $this->settings['rate_limit_requests'] ?? 120 ) );

		$bucket_key = 'sentinel_rl_' . md5( $ip ) . '_' . (int) floor( time() / $window );

		/*
		 * Use WordPress transients (DB-backed) for the request counter so that
		 * rate limiting works on any WordPress installation — including the
		 * default setup that has no persistent object-cache (Redis/Memcached).
		 * wp_cache_incr() with a custom group does NOT persist across HTTP
		 * requests on installations without an external object-cache, making
		 * the counter reset on every request and the rate limiter ineffective.
		 *
		 * The transient TTL is set to 2 * window so that entries expire cleanly
		 * after two full windows without extra housekeeping.
		 */
		$count = (int) get_transient( $bucket_key );
		$count++;
		set_transient( $bucket_key, $count, $window * 2 );

			return;
		}

		// Threshold exceeded — log and block.
		$this->log_blocked( $ip, $count, $limit, $window );

		http_response_code( 429 );
		header( 'Retry-After: ' . $window );
		header( 'Content-Type: text/plain; charset=UTF-8' );
		echo 'Too Many Requests. Please slow down.';
		exit;
	}

	/**
	 * Log the rate-limit block to the activity log.
	 *
	 * @param string $ip     Client IP.
	 * @param int    $count  Requests in current window.
	 * @param int    $limit  Configured limit.
	 * @param int    $window Window size in seconds.
	 */
	private function log_blocked( $ip, $count, $limit, $window ) {
		global $wpdb;
		// Throttle the log entry itself to once per window per IP to avoid
		// flooding the activity log with duplicate entries.
		$log_key = 'sentinel_rl_logged_' . md5( $ip );
		if ( get_transient( $log_key ) ) {
			return;
		}
		set_transient( $log_key, 1, $window );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$wpdb->insert(
			"{$wpdb->prefix}sentinel_activity_log",
			array(
				'user_id'        => 0,
				'event_type'     => 'rate_limit_blocked',
				'event_category' => 'firewall',
				'severity'       => 'medium',
				'description'    => sprintf(
					'Rate limit exceeded: %d requests in %ds window (limit %d). IP: %s',
					$count, $window, $limit, sanitize_text_field( $ip )
				),
				'ip_address'     => sanitize_text_field( $ip ),
				'created_at'     => current_time( 'mysql' ),
			),
			array( '%d', '%s', '%s', '%s', '%s', '%s', '%s' )
		);
	}

	/**
	 * Get the real client IP, respecting common reverse-proxy headers.
	 *
	 * Only trusts proxy headers when the direct connection comes from a
	 * configured list of trusted proxy IPs. Spoofing X-Forwarded-For from
	 * an untrusted source is otherwise trivially easy.
	 *
	 * @return string
	 */
	private function get_client_ip() {
		$remote_addr = isset( $_SERVER['REMOTE_ADDR'] )
			? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) )
			: '0.0.0.0';

		// Only trust proxy headers when the direct connection comes from a
		// trusted proxy. Defaults to empty (proxy headers ignored) unless
		// the admin has configured trusted_proxy_ips in settings.
		$trusted_proxies = (array) ( $this->settings['trusted_proxy_ips'] ?? array() );

		if ( ! empty( $trusted_proxies ) && in_array( $remote_addr, $trusted_proxies, true ) ) {
			$proxy_headers = array( 'HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP', 'HTTP_X_FORWARDED_FOR' );
			foreach ( $proxy_headers as $key ) {
				if ( ! empty( $_SERVER[ $key ] ) ) {
					$val = sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) );
					// X-Forwarded-For can be a comma-separated list; take the first.
					$ip = trim( explode( ',', $val )[0] );
					if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
						return $ip;
					}
				}
			}
		}

		return filter_var( $remote_addr, FILTER_VALIDATE_IP ) ? $remote_addr : '0.0.0.0';
	}
}
