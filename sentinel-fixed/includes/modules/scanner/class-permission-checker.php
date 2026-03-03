<?php
/**
 * Permission Checker.
 *
 * Verifies WordPress file and directory permissions.
 *
 * @package WP_Sentinel_Security
 * @since   1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Permission_Checker
 */
class Permission_Checker {

	/**
	 * Plugin settings.
	 *
	 * @var array
	 */
	private $settings;

	/**
	 * Constructor.
	 *
	 * @param array $settings Plugin settings.
	 */
	public function __construct( $settings = array() ) {
		$this->settings = $settings;
	}

	/**
	 * Run permission checks.
	 *
	 * @return array Array of vulnerability data arrays.
	 */
	public function scan() {
		$vulnerabilities = array();

		// Check critical files.
		$file_checks = array(
			array(
				'path'       => ABSPATH . 'wp-config.php',
				'max_perms'  => '0440',
				'ideal'      => '0400 or 0440',
				'severity'   => 'critical',
				'cvss'       => 9.1,
				'title'      => 'wp-config.php permissions too permissive',
				'description' => 'wp-config.php has overly permissive permissions. This file contains database credentials and should only be readable by the web server user.',
			),
			array(
				'path'       => ABSPATH . '.htaccess',
				'max_perms'  => '0644',
				'ideal'      => '0444',
				'severity'   => 'medium',
				'cvss'       => 5.5,
				'title'      => '.htaccess permissions too permissive',
				'description' => '.htaccess permissions allow modification by too many users. This file controls server configuration.',
			),
		);

		foreach ( $file_checks as $check ) {
			if ( ! file_exists( $check['path'] ) ) {
				continue;
			}

			$perms    = substr( sprintf( '%o', fileperms( $check['path'] ) ), -4 );
			$max_oct  = octdec( $check['max_perms'] );
			$cur_oct  = octdec( $perms );

			if ( $cur_oct > $max_oct ) {
				$vulnerabilities[] = $this->build(
					'perm-' . md5( $check['path'] ),
					$check['title'],
					$check['description'] . sprintf( ' Current permissions: %s. Recommended: %s.', $perms, $check['ideal'] ),
					$check['severity'],
					$check['cvss'],
					sprintf( 'Set permissions to %s using: chmod %s %s', $check['ideal'], $check['ideal'], basename( $check['path'] ) )
				);
			}
		}

		// Check directory permissions.
		$dir_checks = array(
			array(
				'path'       => ABSPATH . 'wp-admin',
				'max_perms'  => '0755',
				'severity'   => 'medium',
				'cvss'       => 5.5,
			),
			array(
				'path'       => ABSPATH . WPINC,
				'max_perms'  => '0755',
				'severity'   => 'medium',
				'cvss'       => 5.5,
			),
			array(
				'path'       => WP_CONTENT_DIR,
				'max_perms'  => '0755',
				'severity'   => 'medium',
				'cvss'       => 5.5,
			),
		);

		foreach ( $dir_checks as $check ) {
			if ( ! is_dir( $check['path'] ) ) {
				continue;
			}

			$perms   = substr( sprintf( '%o', fileperms( $check['path'] ) ), -4 );
			$max_oct = octdec( $check['max_perms'] );
			$cur_oct = octdec( $perms );

			if ( $cur_oct > $max_oct ) {
				$dir_name = basename( $check['path'] );
				$vulnerabilities[] = $this->build(
					'perm-dir-' . md5( $check['path'] ),
					sprintf( 'Directory %s has overly permissive permissions', $dir_name ),
					sprintf( 'The directory "%s" has permissions %s, which is more permissive than recommended (%s).', $dir_name, $perms, $check['max_perms'] ),
					$check['severity'],
					$check['cvss'],
					sprintf( 'Set permissions to %s: chmod %s %s', $check['max_perms'], $check['max_perms'], $dir_name )
				);
			}
		}

		// Check for PHP files in uploads directory.
		$uploads_dir = wp_upload_dir()['basedir'];
		if ( is_dir( $uploads_dir ) ) {
			$php_in_uploads = $this->find_php_files( $uploads_dir );
			foreach ( $php_in_uploads as $php_file ) {
				$vulnerabilities[] = $this->build(
					'perm-php-uploads-' . md5( $php_file ),
					sprintf( 'PHP file found in uploads: %s', basename( $php_file ) ),
					sprintf( 'A PHP file was found in the uploads directory: "%s". PHP files in uploads are a common indicator of a backdoor or malware upload.', $php_file ),
					'high',
					8.1,
					'Investigate this file immediately. If it is not a legitimate upload, delete it and check for additional malware.'
				);
			}
		}

		// Check if WordPress install.php is accessible.
		$install_path = ABSPATH . 'wp-admin/install.php';
		if ( file_exists( $install_path ) ) {
			$response = wp_remote_get(
				admin_url( 'install.php' ),
				array( 'timeout' => 10, 'user-agent' => 'WP Sentinel Security/' . SENTINEL_VERSION )
			);

			if ( ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ) {
				$vulnerabilities[] = $this->build(
					'perm-install-accessible',
					'WordPress install.php is publicly accessible',
					'The WordPress installation script (install.php) is accessible from the internet, potentially allowing reinstallation.',
					'medium',
					5.9,
					'Restrict access to wp-admin/install.php via .htaccess or your web server configuration.'
				);
			}
		}

		return $vulnerabilities;
	}

	/**
	 * Find PHP files recursively within a directory.
	 *
	 * @param string $dir Directory path.
	 * @return array
	 */
	private function find_php_files( $dir ) {
		$found    = array();
		$iterator = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $dir, RecursiveDirectoryIterator::SKIP_DOTS )
		);

		foreach ( $iterator as $file ) {
			if ( $file->isFile() && in_array( strtolower( $file->getExtension() ), array( 'php', 'php5', 'php7', 'phtml' ), true ) ) {
				$found[] = $file->getPathname();
			}
		}

		return $found;
	}

	/**
	 * Build a vulnerability entry.
	 *
	 * @param string $id             Unique ID.
	 * @param string $title          Title.
	 * @param string $description    Description.
	 * @param string $severity       Severity level.
	 * @param float  $cvss           CVSS score.
	 * @param string $recommendation Recommendation.
	 * @return array
	 */
	private function build( $id, $title, $description, $severity, $cvss, $recommendation ) {
		return array(
			'component_type'    => 'file',
			'component_name'    => 'File Permissions',
			'component_version' => '',
			'vulnerability_id'  => $id,
			'title'             => $title,
			'description'       => $description,
			'severity'          => $severity,
			'cvss_score'        => $cvss,
			'cvss_vector'       => '',
			'recommendation'    => $recommendation,
			'reference_urls'    => wp_json_encode( array( 'https://wordpress.org/support/article/hardening-wordpress/' ) ),
		);
	}
}
