<?php
/**
 * Core Integrity Scanner.
 *
 * Verifies WordPress core files against official checksums.
 *
 * @package WP_Sentinel_Security
 * @since   1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Core_Integrity
 */
class Core_Integrity {

	/**
	 * Plugin settings.
	 *
	 * @var array
	 */
	private $settings;

	/**
	 * Directories that should not contain extra PHP files.
	 *
	 * @var array
	 */
	private $protected_dirs = array( 'wp-admin', 'wp-includes' );

	/**
	 * Constructor.
	 *
	 * @param array $settings Plugin settings.
	 */
	public function __construct( $settings = array() ) {
		$this->settings = $settings;
	}

	/**
	 * Run the core integrity scan.
	 *
	 * @return array Array of vulnerability data arrays.
	 */
	public function scan() {
		$vulnerabilities = array();
		$checksums       = $this->get_checksums();

		if ( null === $checksums ) {
			return array(
				array(
					'component_type'    => 'core',
					'component_name'    => 'WordPress Core',
					'component_version' => get_bloginfo( 'version' ),
					'vulnerability_id'  => 'core-integrity-api-unreachable',
					'title'             => 'Core integrity check skipped: WordPress.org API unreachable',
					'description'       => 'The WordPress.org checksums API could not be reached. Core file integrity could not be verified. Please check your server\'s outbound connectivity.',
					'severity'          => 'info',
					'cvss_score'        => 0.0,
					'cvss_vector'       => '',
					'recommendation'    => 'Ensure your server can reach api.wordpress.org and retry the scan.',
					'reference_urls'    => wp_json_encode( array( 'https://api.wordpress.org/core/checksums/1.0/' ) ),
				),
			);
		}

		if ( empty( $checksums ) ) {
			return $vulnerabilities;
		}

		// Check each expected file.
		foreach ( $checksums as $relative_path => $expected_md5 ) {
			$full_path = ABSPATH . $relative_path;

			if ( ! file_exists( $full_path ) ) {
				$vulnerabilities[] = array(
					'component_type'    => 'core',
					'component_name'    => 'WordPress Core',
					'component_version' => get_bloginfo( 'version' ),
					'vulnerability_id'  => 'core-missing-' . md5( $relative_path ),
					'title'             => sprintf( 'Missing core file: %s', $relative_path ),
					'description'       => sprintf( 'The WordPress core file "%s" is missing. This may indicate a corrupted installation.', $relative_path ),
					'severity'          => 'high',
					'cvss_score'        => 7.5,
					'cvss_vector'       => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N',
					'recommendation'    => 'Reinstall WordPress core files using the WordPress admin update process or by downloading a fresh copy from wordpress.org.',
					'reference_urls'    => wp_json_encode( array( 'https://wordpress.org/download/' ) ),
				);
				continue;
			}

			// Compare MD5 hash.
			$actual_md5 = md5_file( $full_path );
			if ( $actual_md5 !== $expected_md5 ) {
				$vulnerabilities[] = array(
					'component_type'    => 'core',
					'component_name'    => 'WordPress Core',
					'component_version' => get_bloginfo( 'version' ),
					'vulnerability_id'  => 'core-modified-' . md5( $relative_path ),
					'title'             => sprintf( 'Modified core file: %s', $relative_path ),
					'description'       => sprintf( 'The WordPress core file "%s" has been modified. Expected MD5: %s, Actual MD5: %s.', $relative_path, $expected_md5, $actual_md5 ),
					'severity'          => 'critical',
					'cvss_score'        => 9.8,
					'cvss_vector'       => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
					'recommendation'    => 'Immediately review the modified file for malicious code and restore the original from a known-good source.',
					'reference_urls'    => wp_json_encode( array( 'https://wordpress.org/download/' ) ),
				);
			}
		}

		// Detect extra PHP files in protected directories.
		foreach ( $this->protected_dirs as $dir ) {
			$dir_path = ABSPATH . $dir;
			if ( ! is_dir( $dir_path ) ) {
				continue;
			}

			$extra = $this->find_extra_php_files( $dir_path, $checksums );
			foreach ( $extra as $extra_file ) {
				$relative = str_replace( ABSPATH, '', $extra_file );
				$vulnerabilities[] = array(
					'component_type'    => 'core',
					'component_name'    => 'WordPress Core',
					'component_version' => get_bloginfo( 'version' ),
					'vulnerability_id'  => 'core-extra-' . md5( $relative ),
					'title'             => sprintf( 'Unknown PHP file in %s: %s', $dir, $relative ),
					'description'       => sprintf( 'An unexpected PHP file was found in a protected WordPress directory: "%s". This may indicate a backdoor or malware.', $relative ),
					'severity'          => 'medium',
					'cvss_score'        => 6.5,
					'cvss_vector'       => 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
					'recommendation'    => 'Investigate this file immediately. If it is not a legitimate WordPress file, remove it.',
					'reference_urls'    => wp_json_encode( array() ),
				);
			}
		}

		return $vulnerabilities;
	}

	/**
	 * Fetch core file checksums from the WordPress.org API.
	 *
	 * Results are cached for 24 hours.
	 *
	 * @return array Associative array of relative_path => md5_hash.
	 */
	private function get_checksums() {
		global $wp_version;

		$locale      = get_locale();
		$cache_key   = 'core_checksums_' . $wp_version . '_' . $locale;
		$cached      = Sentinel_Cache::get( $cache_key );

		if ( false !== $cached ) {
			return $cached;
		}

		$api_url  = add_query_arg(
			array(
				'version' => $wp_version,
				'locale'  => $locale,
			),
			'https://api.wordpress.org/core/checksums/1.0/'
		);

		$response = wp_remote_get(
			$api_url,
			array(
				'timeout'    => 30,
				'user-agent' => 'WP Sentinel Security/' . SENTINEL_VERSION,
			)
		);

		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return null;
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( empty( $body['checksums'] ) ) {
			return array();
		}

		$checksums = $body['checksums'];
		Sentinel_Cache::set( $cache_key, $checksums, DAY_IN_SECONDS );

		return $checksums;
	}

	/**
	 * Find PHP files in a directory that are not in the checksum list.
	 *
	 * @param string $dir_path  Absolute directory path.
	 * @param array  $checksums Known checksums (relative paths as keys).
	 * @return array Absolute paths of extra files.
	 */
	private function find_extra_php_files( $dir_path, $checksums ) {
		$extra    = array();
		$iterator = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $dir_path, RecursiveDirectoryIterator::SKIP_DOTS )
		);

		foreach ( $iterator as $file ) {
			if ( ! $file->isFile() || 'php' !== strtolower( $file->getExtension() ) ) {
				continue;
			}

			$relative = str_replace( ABSPATH, '', wp_normalize_path( $file->getPathname() ) );
			if ( ! isset( $checksums[ $relative ] ) ) {
				$extra[] = $file->getPathname();
			}
		}

		return $extra;
	}
}
