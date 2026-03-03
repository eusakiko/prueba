<?php
/**
 * Cache utility class.
 *
 * Static transient wrapper with a consistent 'sentinel_' key prefix.
 *
 * @package WP_Sentinel_Security
 * @since   1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Sentinel_Cache
 */
class Sentinel_Cache {

	/**
	 * Transient key prefix.
	 *
	 * @var string
	 */
	const PREFIX = 'sentinel_';

	/**
	 * Retrieve a cached value.
	 *
	 * @param string $key Cache key (without prefix).
	 * @return mixed|false Cached value or false if not found.
	 */
	public static function get( $key ) {
		return get_transient( self::PREFIX . sanitize_key( $key ) );
	}

	/**
	 * Store a value in the cache.
	 *
	 * @param string $key        Cache key (without prefix).
	 * @param mixed  $value      Value to cache.
	 * @param int    $expiration Expiration time in seconds. 0 = no expiration.
	 * @return bool True on success, false on failure.
	 */
	public static function set( $key, $value, $expiration = 3600 ) {
		return set_transient( self::PREFIX . sanitize_key( $key ), $value, absint( $expiration ) );
	}

	/**
	 * Delete a cached value.
	 *
	 * @param string $key Cache key (without prefix).
	 * @return bool True on success, false on failure.
	 */
	public static function delete( $key ) {
		return delete_transient( self::PREFIX . sanitize_key( $key ) );
	}

	/**
	 * Flush all sentinel-prefixed transients.
	 *
	 * @return void
	 */
	public static function flush_all() {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s",
				$wpdb->esc_like( '_transient_' . self::PREFIX ) . '%',
				$wpdb->esc_like( '_transient_timeout_' . self::PREFIX ) . '%'
			)
		);
	}
}
