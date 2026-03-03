<?php
/**
 * Secure Cookie Handler.
 *
 * Centralizes cookie access, normalization, and creation with secure defaults
 * (HttpOnly, Secure when HTTPS, SameSite=Lax). Prevents header-injection via
 * strict name/value filtering.
 *
 * Inspired by Sucuri's SucuriScanCookie class, adapted to the WP Sentinel
 * architecture.
 *
 * Usage:
 *   Sentinel_Cookie::get( 'my_cookie' )
 *   Sentinel_Cookie::set( 'my_cookie', 'value', 3600 )
 *   Sentinel_Cookie::delete( 'my_cookie' )
 *
 * @package WP_Sentinel_Security
 * @since   2.8.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Sentinel_Cookie
 */
class Sentinel_Cookie {

	/**
	 * Allowed cookie name characters.
	 * Restricted subset of RFC 6265 to avoid header injection.
	 */
	const NAME_PATTERN = '/^[A-Za-z0-9._-]{1,64}$/';

	/**
	 * Allowed cookie value characters (opaque tokens only).
	 * Callers that need URL-safe base64 or hex values fall within this set.
	 */
	const VALUE_PATTERN = '/^[A-Za-z0-9._~+\\/=-]{0,512}$/';

	/** Maximum cookie lifetime (1 year). */
	const MAX_TTL = 31536000;

	// ── Public API ─────────────────────────────────────────────────────────────

	/**
	 * Check whether a named cookie is present in the current request.
	 *
	 * @param string $name Cookie name.
	 * @return bool
	 */
	public static function has( $name ) {
		return '' !== self::normalize_name( $name ) && isset( $_COOKIE[ self::normalize_name( $name ) ] );
	}

	/**
	 * Retrieve a cookie value (filtered).
	 *
	 * @param string $name    Cookie name.
	 * @param string $default Fallback value returned when cookie is absent or value is invalid.
	 * @return string Filtered value, or $default.
	 */
	public static function get( $name, $default = '' ) {
		$name = self::normalize_name( $name );

		if ( '' === $name || ! isset( $_COOKIE[ $name ] ) ) {
			return $default;
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
		$raw      = (string) $_COOKIE[ $name ];
		$filtered = self::filter_value( $raw );

		// If filter stripped everything but original was non-empty, return default
		// (don't silently return an empty string that looks like "no value").
		return ( '' === $filtered && '' !== $raw ) ? $default : $filtered;
	}

	/**
	 * Set a cookie with secure defaults.
	 *
	 * @param string $name     Cookie name.
	 * @param string $value    Cookie value (will be filtered; if invalid, empty string is stored).
	 * @param int    $ttl      Lifetime in seconds. 0 = session cookie.
	 * @param string $path     Path scope.
	 * @param string $domain   Domain scope (default: current domain).
	 * @param string $samesite SameSite policy: None | Lax | Strict.
	 * @return bool True if the header was successfully set.
	 */
	public static function set(
		$name,
		$value,
		$ttl      = 0,
		$path     = '/',
		$domain   = '',
		$samesite = 'Lax'
	) {
		$name = self::normalize_name( $name );
		if ( '' === $name ) {
			return false;
		}

		$ttl    = max( 0, min( self::MAX_TTL, (int) $ttl ) );
		$value  = self::filter_value( (string) $value );
		$expire = $ttl > 0 ? ( time() + $ttl ) : 0;
		$secure = self::is_secure();

		// SameSite=None requires Secure.
		$samesite_clean = in_array( $samesite, array( 'None', 'Lax', 'Strict' ), true ) ? $samesite : 'Lax';
		if ( 'None' === $samesite_clean ) {
			$secure = true;
		}

		// PHP 7.3+ supports the options array with samesite.
		if ( version_compare( PHP_VERSION, '7.3', '>=' ) ) {
			return setcookie( $name, $value, array(
				'expires'  => $expire,
				'path'     => $path,
				'domain'   => $domain,
				'secure'   => $secure,
				'httponly' => true,
				'samesite' => $samesite_clean,
			) );
		}

		// Fallback: append SameSite via header() for older PHP.
		$result = setcookie( $name, $value, $expire, $path, $domain, $secure, true );
		if ( $result && 'Lax' !== $samesite_clean ) {
			// Overwrite the Set-Cookie header with samesite appended.
			header(
				sprintf(
					'Set-Cookie: %s=%s; Max-Age=%d; path=%s%s%s; HttpOnly; SameSite=%s',
					rawurlencode( $name ),
					rawurlencode( $value ),
					$ttl,
					$path,
					$domain ? '; domain=' . $domain : '',
					$secure  ? '; Secure' : '',
					$samesite_clean
				),
				false
			);
		}
		return $result;
	}

	/**
	 * Expire (delete) a cookie on the client side.
	 *
	 * @param string $name   Cookie name.
	 * @param string $path   Path scope.
	 * @param string $domain Domain scope.
	 * @return bool
	 */
	public static function delete( $name, $path = '/', $domain = '' ) {
		$name = self::normalize_name( $name );
		if ( '' === $name ) {
			return false;
		}

		// Unset from superglobal so same-request reads don't see the stale value.
		if ( isset( $_COOKIE[ $name ] ) ) {
			unset( $_COOKIE[ $name ] );
		}

		return setcookie( $name, '', time() - 3600, $path, $domain, self::is_secure(), true );
	}

	// ── Helpers ────────────────────────────────────────────────────────────────

	/**
	 * Validate and return a normalized cookie name, or '' if invalid.
	 *
	 * @param string $name Raw name.
	 * @return string
	 */
	private static function normalize_name( $name ) {
		if ( ! is_string( $name ) ) {
			return '';
		}
		$name = trim( $name );
		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		return ( '' !== $name && (bool) @preg_match( self::NAME_PATTERN, $name ) ) ? $name : '';
	}

	/**
	 * Filter a value through the allowed character set.
	 *
	 * Returns empty string if the value does not match (caller decides what to
	 * do with an empty string — usually treat as absent).
	 *
	 * @param string $value Raw value.
	 * @return string
	 */
	private static function filter_value( $value ) {
		if ( ! is_string( $value ) ) {
			return '';
		}
		$value = trim( $value );
		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( '' === $value || ! (bool) @preg_match( self::VALUE_PATTERN, $value ) ) {
			return '';
		}
		return sanitize_text_field( $value );
	}

	/**
	 * Whether the current request is served over HTTPS.
	 *
	 * @return bool
	 */
	private static function is_secure() {
		if ( function_exists( 'is_ssl' ) ) {
			return is_ssl();
		}
		$https = isset( $_SERVER['HTTPS'] ) ? (string) $_SERVER['HTTPS'] : '';
		$port  = isset( $_SERVER['SERVER_PORT'] ) ? (int) $_SERVER['SERVER_PORT'] : 0;
		return ( '' !== $https && 'off' !== strtolower( $https ) ) || 443 === $port;
	}
}
