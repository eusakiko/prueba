<?php
/**
 * Helper utility class.
 *
 * Static utility methods used throughout the plugin.
 *
 * @package WP_Sentinel_Security
 * @since   1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Sentinel_Helper
 */
class Sentinel_Helper {

	/**
	 * Get the real client IP address.
	 *
	 * Checks Cloudflare, load-balancer, and proxy headers before falling back
	 * to REMOTE_ADDR.
	 *
	 * @return string Client IP address.
	 */
	public static function get_client_ip() {
		$settings        = get_option( 'sentinel_settings', array() );
		$trust_proxy     = ! empty( $settings['trust_proxy_headers'] );
		$trusted_proxies = (array) ( $settings['trusted_proxy_ips'] ?? array() );

		// REMOTE_ADDR is the only unconditionally trusted value — it comes from
		// the TCP connection itself and cannot be spoofed by the client.
		$remote_addr = isset( $_SERVER['REMOTE_ADDR'] )
			? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) )
			: '0.0.0.0';

		// Only honour proxy headers when the direct connection originates from
		// a configured trusted proxy IP.  Without this check any client can
		// send X-Forwarded-For: 127.0.0.1 to spoof localhost and bypass
		// all firewall rules (IP spoofing vulnerability fix).
		if ( $trust_proxy && ! empty( $trusted_proxies ) && in_array( $remote_addr, $trusted_proxies, true ) ) {
			$proxy_headers = array(
				'HTTP_CF_CONNECTING_IP',
				'HTTP_X_FORWARDED_FOR',
				'HTTP_X_REAL_IP',
			);
			foreach ( $proxy_headers as $header ) {
				if ( ! empty( $_SERVER[ $header ] ) ) {
					$ip = trim( explode( ',', sanitize_text_field( wp_unslash( $_SERVER[ $header ] ) ) )[0] );
					// Accept private-range IPs: internal load balancers legitimately
					// forward private addresses as the real client IP (Bug #7 fix).
					if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
						return $ip;
					}
				}
			}
		}

		return filter_var( $remote_addr, FILTER_VALIDATE_IP ) ? $remote_addr : '0.0.0.0';
	}

	/**
	 * Format bytes as human-readable file size.
	 *
	 * @param int $bytes Number of bytes.
	 * @return string Formatted size string.
	 */
	public static function format_file_size( $bytes ) {
		$bytes = (int) $bytes;
		if ( $bytes < 0 ) {
			return '0 B';
		}

		$units = array( 'B', 'KB', 'MB', 'GB', 'TB' );
		$i     = 0;

		while ( $bytes >= 1024 && $i < count( $units ) - 1 ) {
			$bytes /= 1024;
			$i++;
		}

		return round( $bytes, 2 ) . ' ' . $units[ $i ];
	}

	/**
	 * Sanitize a filesystem path.
	 *
	 * Resolves the path, ensures it stays within ABSPATH, and normalizes separators.
	 *
	 * @param string $path Raw path.
	 * @return string|false Sanitized path, or false if outside ABSPATH.
	 */
	public static function sanitize_path( $path ) {
		$path = realpath( $path );

		if ( false === $path ) {
			return false;
		}

		// Ensure path is within the WordPress root.
		if ( 0 !== strpos( $path, realpath( ABSPATH ) ) ) {
			return false;
		}

		return wp_normalize_path( $path );
	}

	/**
	 * Validate a hash string.
	 *
	 * @param string $hash Hash value to validate.
	 * @param string $algo Hash algorithm ('sha256', 'md5', 'sha1').
	 * @return bool True if the hash is valid for the given algorithm.
	 */
	public static function is_valid_hash( $hash, $algo = 'sha256' ) {
		$lengths = array(
			'sha256' => 64,
			'sha1'   => 40,
			'md5'    => 32,
		);

		if ( ! isset( $lengths[ $algo ] ) ) {
			return false;
		}

		return (bool) preg_match( '/^[a-f0-9]{' . $lengths[ $algo ] . '}$/i', $hash );
	}

	/**
	 * Get the current WordPress version.
	 *
	 * @return string
	 */
	public static function get_wp_version() {
		global $wp_version;
		return $wp_version;
	}

	/**
	 * Get the current PHP version.
	 *
	 * @return string
	 */
	public static function get_php_version() {
		return PHP_VERSION;
	}

	/**
	 * Get server environment information.
	 *
	 * @return array
	 */
	public static function get_server_info() {
		global $wpdb;

		return array(
			'server'         => isset( $_SERVER['SERVER_SOFTWARE'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) : 'Unknown',
			'php_version'    => PHP_VERSION,
			'db_version'     => $wpdb->db_version(),
			'memory_limit'   => ini_get( 'memory_limit' ),
			'max_execution'  => ini_get( 'max_execution_time' ),
			'upload_max'     => ini_get( 'upload_max_filesize' ),
			'os'             => PHP_OS,
			'wp_version'     => self::get_wp_version(),
			'wp_memory'      => WP_MEMORY_LIMIT,
			'wp_debug'       => defined( 'WP_DEBUG' ) && WP_DEBUG,
			'multisite'      => is_multisite(),
		);
	}
}
