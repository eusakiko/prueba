<?php
/**
 * Environment Fingerprint — Complete server/environment fingerprinting.
 *
 * @package WP_Sentinel_Security
 * @since   1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Environment_Fingerprint
 */
class Environment_Fingerprint {

	/**
	 * Collect a comprehensive fingerprint of the environment.
	 *
	 * @return array Nested fingerprint data.
	 */
	public function fingerprint() {
		return array(
			'server'           => $this->get_server_info(),
			'php'              => $this->get_php_info(),
			'database'         => $this->get_database_info(),
			'wordpress'        => $this->get_wordpress_info(),
			'hosting'          => $this->get_hosting_info(),
			'security_headers' => $this->get_security_headers(),
			'network'          => $this->get_network_info(),
		);
	}

	/**
	 * Gather web-server information.
	 *
	 * @return array
	 */
	private function get_server_info() {
		$software = isset( $_SERVER['SERVER_SOFTWARE'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) : 'unknown';

		$type = 'unknown';
		if ( false !== stripos( $software, 'nginx' ) ) {
			$type = 'nginx';
		} elseif ( false !== stripos( $software, 'apache' ) ) {
			$type = 'apache';
		} elseif ( false !== stripos( $software, 'litespeed' ) ) {
			$type = 'litespeed';
		} elseif ( false !== stripos( $software, 'iis' ) ) {
			$type = 'iis';
		}

		$os = 'unknown';
		if ( defined( 'PHP_OS' ) ) {
			$raw_os = strtolower( PHP_OS );
			if ( false !== strpos( $raw_os, 'linux' ) ) {
				$os = 'Linux';
			} elseif ( false !== strpos( $raw_os, 'win' ) ) {
				$os = 'Windows';
			} elseif ( false !== strpos( $raw_os, 'darwin' ) ) {
				$os = 'macOS';
			} elseif ( false !== strpos( $raw_os, 'freebsd' ) ) {
				$os = 'FreeBSD';
			} else {
				$os = PHP_OS;
			}
		}

		return array(
			'software' => $software,
			'type'     => $type,
			'os'       => $os,
		);
	}

	/**
	 * Gather PHP runtime information.
	 *
	 * Returns security-relevant extension details only; the full extension list
	 * is omitted to reduce fingerprint exposure.
	 *
	 * @return array
	 */
	private function get_php_info() {
		$version = phpversion();
		$sapi    = php_sapi_name();
		$memory  = ini_get( 'memory_limit' );

		// EOL check: PHP 7.4 and below are EOL.
		$major_minor = (float) $version;
		$is_eol      = $major_minor < 8.0;

		// Report only the count of loaded extensions, not the full list, to
		// limit unnecessary fingerprint exposure.
		$extension_count = count( get_loaded_extensions() );

		return array(
			'version'          => $version,
			'sapi'             => $sapi,
			'memory'           => $memory,
			'extension_count'  => $extension_count,
			'opcache'          => function_exists( 'opcache_get_status' ) && opcache_get_status( false ) !== false,
			'redis'            => extension_loaded( 'redis' ),
			'memcached'        => extension_loaded( 'memcached' ),
			'is_eol'           => $is_eol,
		);
	}

	/**
	 * Gather database server information.
	 *
	 * @return array
	 */
	private function get_database_info() {
		global $wpdb;

		if ( ! isset( $wpdb ) || ! $wpdb ) {
			return array(
				'version' => 'unknown',
				'type'    => 'unknown',
				'charset' => 'unknown',
				'prefix'  => 'unknown',
			);
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$db_version = $wpdb->get_var( 'SELECT VERSION()' );

		$is_mariadb = false !== stripos( (string) $db_version, 'mariadb' );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$charset = $wpdb->get_var( 'SELECT @@character_set_database' );

		return array(
			'version'   => (string) $db_version,
			'type'      => $is_mariadb ? 'MariaDB' : 'MySQL',
			'charset'   => (string) $charset,
			'prefix'    => $wpdb->prefix,
		);
	}

	/**
	 * Gather WordPress installation information.
	 *
	 * @return array
	 */
	private function get_wordpress_info() {
		global $wp_version;

		$active_plugins = get_option( 'active_plugins', array() );
		$current_theme  = wp_get_theme();

		// Check if current WP is the latest version.
		$is_latest  = false;
		$latest_ver = get_transient( 'sentinel_wp_latest_version' );

		if ( false === $latest_ver ) {
			$response = wp_remote_get(
				'https://api.wordpress.org/core/version-check/1.7/',
				array( 'timeout' => 10 )
			);

			if ( ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ) {
				$data = json_decode( wp_remote_retrieve_body( $response ), true );
				if ( ! empty( $data['offers'][0]['version'] ) ) {
					$latest_ver = $data['offers'][0]['version'];
					set_transient( 'sentinel_wp_latest_version', $latest_ver, 6 * HOUR_IN_SECONDS );
				}
			}
		}

		if ( $latest_ver ) {
			$is_latest = version_compare( $wp_version, $latest_ver, '>=' );
		}

		return array(
			'version'    => $wp_version,
			'multisite'  => is_multisite(),
			'plugins'    => count( $active_plugins ),
			'theme'      => $current_theme->get_stylesheet(),
			'debug'      => defined( 'WP_DEBUG' ) && WP_DEBUG,
			'ssl'        => is_ssl(),
			'is_latest'  => $is_latest,
		);
	}

	/**
	 * Detect hosting environment and WAF/CDN presence.
	 *
	 * @return array
	 */
	private function get_hosting_info() {
		$hostname = gethostname();

		// Cloud provider detection by hostname.
		$cloud = 'unknown';
		if ( $hostname ) {
			if ( preg_match( '/\.amazonaws\.com$/i', $hostname ) || preg_match( '/^ip-\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}/i', $hostname ) ) {
				$cloud = 'AWS';
			} elseif ( preg_match( '/\.googleusercontent\.com$/i', $hostname ) || preg_match( '/\.googleapis\.com$/i', $hostname ) ) {
				$cloud = 'GCP';
			} elseif ( preg_match( '/\.azure\.|\.windows\.net$/i', $hostname ) ) {
				$cloud = 'Azure';
			}
		}

		// Control panel detection.
		$cpanel  = file_exists( '/usr/local/cpanel/cpanel' ) || file_exists( '/etc/cpanel' );
		$plesk   = file_exists( '/opt/psa/version' ) || file_exists( '/usr/local/psa/version' );

		// Docker detection: check for .dockerenv first (fast), then /proc/1/cgroup (with limited read).
		$docker = file_exists( '/.dockerenv' );
		if ( ! $docker && file_exists( '/proc/1/cgroup' ) ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
			$cgroup_content = @file_get_contents( '/proc/1/cgroup', false, null, 0, 1024 );
			$docker         = false !== $cgroup_content && false !== strpos( $cgroup_content, 'docker' );
		}

		// CDN / WAF detection from incoming HTTP headers.
		$cf_ray    = isset( $_SERVER['HTTP_CF_RAY'] ) || isset( $_SERVER['HTTP_CF_CONNECTING_IP'] );
		$cf_worker = isset( $_SERVER['HTTP_CF_WORKER'] );
		$sucuri_id = isset( $_SERVER['HTTP_X_SUCURI_ID'] );

		return array(
			'cloud'  => $cloud,
			'cpanel' => $cpanel,
			'plesk'  => $plesk,
			'docker' => $docker,
			'waf'    => array(
				'cloudflare' => $cf_ray || $cf_worker,
				'sucuri'     => $sucuri_id,
			),
		);
	}

	/**
	 * Fetch and evaluate HTTP security headers for the home URL.
	 *
	 * @return array Map of header name => value|false.
	 */
	private function get_security_headers() {
		$headers_to_check = array(
			'Strict-Transport-Security',
			'Content-Security-Policy',
			'X-Frame-Options',
			'X-Content-Type-Options',
			'Referrer-Policy',
			'Permissions-Policy',
			'X-XSS-Protection',
		);

		$result = array();

		$response = wp_remote_get(
			home_url( '/' ),
			array(
				'timeout'     => 10,
				'sslverify'   => false,
				'redirection' => 0,
			)
		);

		if ( is_wp_error( $response ) ) {
			foreach ( $headers_to_check as $header ) {
				$result[ $header ] = false;
			}
			return $result;
		}

		$response_headers = wp_remote_retrieve_headers( $response );

		foreach ( $headers_to_check as $header ) {
			$lower  = strtolower( $header );
			$value  = $response_headers->offsetExists( $lower ) ? $response_headers->offsetGet( $lower ) : false;
			$result[ $header ] = $value;
		}

		return $result;
	}

	/**
	 * Gather network and URL information.
	 *
	 * Server IP is intentionally omitted from the returned data to avoid
	 * exposing internal infrastructure details. Only the `is_local` flag
	 * (derived from the IP) is retained for security posture assessment.
	 *
	 * @return array
	 */
	private function get_network_info() {
		$server_ip = isset( $_SERVER['SERVER_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SERVER_ADDR'] ) ) : '';

		return array(
			'home_url' => home_url(),
			'site_url' => site_url(),
			'ssl'      => is_ssl(),
			'is_local' => in_array( $server_ip, array( '127.0.0.1', '::1', 'localhost' ), true ),
		);
	}
}
