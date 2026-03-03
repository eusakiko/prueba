<?php
/**
 * Configuration Analyzer.
 *
 * Performs 16+ security configuration checks on the WordPress installation.
 *
 * @package WP_Sentinel_Security
 * @since   1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Config_Analyzer
 */
class Config_Analyzer {

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
	 * Run all configuration checks.
	 *
	 * @return array Array of vulnerability data arrays.
	 */
	public function scan() {
		$vulnerabilities = array();

		$checks = array(
			'check_wp_debug',
			'check_wp_debug_log',
			'check_wp_debug_display',
			'check_disallow_file_edit',
			'check_disallow_file_mods',
			'check_force_ssl_admin',
			'check_db_password',
			'check_table_prefix',
			'check_security_keys',
			'check_php_version',
			'check_expose_php',
			'check_allow_url_fopen',
			'check_display_errors',
			'check_xmlrpc',
			'check_user_enumeration',
			'check_wp_version_exposure',
			'check_sensitive_files',
			'check_directory_listing',
		);

		foreach ( $checks as $check ) {
			$result = $this->$check();
			if ( $result ) {
				$vulnerabilities[] = $result;
			}
		}

		return $vulnerabilities;
	}

	// -----------------------------------------------------------------------
	// Individual checks
	// -----------------------------------------------------------------------

	/** @return array|null */
	private function check_wp_debug() {
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			return $this->build( 'config-wp-debug', 'WP_DEBUG is enabled', 'WP_DEBUG is enabled on your site. Debug mode may expose sensitive information to visitors.', 'medium', 5.3, "Set define('WP_DEBUG', false); in wp-config.php." );
		}
		return null;
	}

	/** @return array|null */
	private function check_wp_debug_log() {
		if ( defined( 'WP_DEBUG_LOG' ) && WP_DEBUG_LOG ) {
			return $this->build( 'config-wp-debug-log', 'WP_DEBUG_LOG is enabled', 'Debug log is being written to disk. The debug.log file may be publicly accessible.', 'medium', 5.0, "Set define('WP_DEBUG_LOG', false); in wp-config.php or move it outside the webroot." );
		}
		return null;
	}

	/** @return array|null */
	private function check_wp_debug_display() {
		if ( defined( 'WP_DEBUG_DISPLAY' ) && WP_DEBUG_DISPLAY ) {
			return $this->build( 'config-wp-debug-display', 'WP_DEBUG_DISPLAY is enabled', 'Errors are being displayed on screen. This can expose sensitive server information.', 'medium', 5.3, "Set define('WP_DEBUG_DISPLAY', false); in wp-config.php." );
		}
		return null;
	}

	/** @return array|null */
	private function check_disallow_file_edit() {
		if ( ! defined( 'DISALLOW_FILE_EDIT' ) || ! DISALLOW_FILE_EDIT ) {
			return $this->build( 'config-disallow-file-edit', 'File editing is enabled in the admin', 'The WordPress theme/plugin editor is enabled. Attackers with admin access can inject malicious code.', 'high', 7.2, "Add define('DISALLOW_FILE_EDIT', true); to wp-config.php." );
		}
		return null;
	}

	/** @return array|null */
	private function check_disallow_file_mods() {
		if ( ! defined( 'DISALLOW_FILE_MODS' ) || ! DISALLOW_FILE_MODS ) {
			return $this->build( 'config-disallow-file-mods', 'File modifications are allowed', 'WordPress can install and update plugins/themes. Consider disabling this on production sites.', 'low', 3.1, "Add define('DISALLOW_FILE_MODS', true); to wp-config.php." );
		}
		return null;
	}

	/** @return array|null */
	private function check_force_ssl_admin() {
		if ( ! defined( 'FORCE_SSL_ADMIN' ) || ! FORCE_SSL_ADMIN ) {
			return $this->build( 'config-force-ssl-admin', 'FORCE_SSL_ADMIN is not set', 'Admin sessions may not be forced over HTTPS, exposing credentials to eavesdropping.', 'medium', 5.9, "Add define('FORCE_SSL_ADMIN', true); to wp-config.php." );
		}
		return null;
	}

	/** @return array|null */
	private function check_db_password() {
		if ( defined( 'DB_PASSWORD' ) ) {
			$pw = DB_PASSWORD;
			if ( empty( $pw ) || strlen( $pw ) < 8 ) {
				return $this->build( 'config-db-password', 'Weak or empty database password', 'The database password is empty or shorter than 8 characters, making it easy to guess.', 'critical', 9.8, 'Set a strong, unique database password of at least 16 characters.' );
			}
		}
		return null;
	}

	/** @return array|null */
	private function check_table_prefix() {
		global $wpdb;
		if ( 'wp_' === $wpdb->prefix ) {
			return $this->build( 'config-table-prefix', 'Default database table prefix in use', 'The WordPress table prefix is the default "wp_". Automated SQL injection attacks commonly target this prefix.', 'medium', 5.3, 'Change the table prefix in wp-config.php and rename all tables.' );
		}
		return null;
	}

	/** @return array|null */
	private function check_security_keys() {
		$constants = array( 'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY', 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT' );
		$default   = 'put your unique phrase here';

		foreach ( $constants as $key ) {
			if ( ! defined( $key ) || empty( constant( $key ) ) || false !== strpos( constant( $key ), $default ) ) {
				return $this->build( 'config-security-keys', 'Missing or default WordPress security keys/salts', 'One or more security keys or salts are missing or using the default placeholder value.', 'high', 7.5, 'Generate new keys at https://api.wordpress.org/secret-key/1.1/salt/ and update wp-config.php.' );
			}
		}
		return null;
	}

	/** @return array|null */
	private function check_php_version() {
		$eol_versions = array( '5', '7.0', '7.1', '7.2', '7.3' );
		foreach ( $eol_versions as $v ) {
			if ( version_compare( PHP_VERSION, $v . '.999', '<=' ) && version_compare( PHP_VERSION, $v, '>=' ) ) {
				return $this->build( 'config-php-eol', sprintf( 'End-of-life PHP version (%s)', PHP_VERSION ), sprintf( 'PHP %s is end-of-life and no longer receives security patches.', PHP_VERSION ), 'high', 7.5, 'Upgrade to a supported PHP version (8.1 or higher recommended).' );
			}
		}
		return null;
	}

	/** @return array|null */
	private function check_expose_php() {
		if ( '1' === ini_get( 'expose_php' ) ) {
			return $this->build( 'config-expose-php', 'PHP version exposed in HTTP headers', 'The expose_php directive reveals your PHP version in response headers, helping attackers target known exploits.', 'low', 3.7, "Set expose_php = Off in your php.ini or .htaccess." );
		}
		return null;
	}

	/** @return array|null */
	private function check_allow_url_fopen() {
		if ( '1' === ini_get( 'allow_url_fopen' ) ) {
			return $this->build( 'config-allow-url-fopen', 'allow_url_fopen is enabled', 'allow_url_fopen allows PHP to treat remote URLs as local files, which can be abused in file inclusion attacks.', 'medium', 5.3, "Set allow_url_fopen = Off in php.ini if not needed." );
		}
		return null;
	}

	/** @return array|null */
	private function check_display_errors() {
		if ( '1' === ini_get( 'display_errors' ) ) {
			return $this->build( 'config-display-errors', 'PHP display_errors is enabled', 'PHP errors are displayed to visitors, potentially revealing sensitive application and server information.', 'medium', 5.3, "Set display_errors = Off in php.ini." );
		}
		return null;
	}

	/** @return array|null */
	private function check_xmlrpc() {
		$response = wp_remote_get(
			home_url( '/xmlrpc.php' ),
			array( 'timeout' => 10, 'user-agent' => 'WP Sentinel Security/' . SENTINEL_VERSION )
		);

		if ( ! is_wp_error( $response ) ) {
			$code = wp_remote_retrieve_response_code( $response );
			if ( 200 === $code || 405 === $code ) {
				return $this->build( 'config-xmlrpc', 'XML-RPC is accessible', 'The XML-RPC endpoint is publicly accessible and can be abused for brute-force attacks and DDoS amplification.', 'medium', 5.8, 'Disable XML-RPC using a security plugin or by adding a filter to the xmlrpc_enabled hook.' );
			}
		}
		return null;
	}

	/** @return array|null */
	private function check_user_enumeration() {
		$response = wp_remote_get(
			add_query_arg( array( 'author' => 1 ), home_url( '/' ) ),
			array( 'timeout' => 10, 'redirection' => 0, 'user-agent' => 'WP Sentinel Security/' . SENTINEL_VERSION )
		);

		if ( ! is_wp_error( $response ) ) {
			$location = wp_remote_retrieve_header( $response, 'location' );
			if ( $location && preg_match( '#/author/[^/]+/#i', $location ) ) {
				return $this->build( 'config-user-enumeration', 'User enumeration via REST API/author archives', 'WordPress is redirecting ?author=N queries to author slug URLs, leaking usernames to attackers.', 'medium', 5.3, 'Disable author archives or redirect them to prevent username disclosure.' );
			}
		}
		return null;
	}

	/** @return array|null */
	private function check_wp_version_exposure() {
		$response = wp_remote_get(
			home_url( '/' ),
			array( 'timeout' => 10, 'user-agent' => 'WP Sentinel Security/' . SENTINEL_VERSION )
		);

		if ( ! is_wp_error( $response ) ) {
			$body = wp_remote_retrieve_body( $response );
			if ( preg_match( '#<meta name=["\']generator["\'] content=["\']WordPress ' . preg_quote( get_bloginfo( 'version' ), '#' ) . '["\']#i', $body ) ) {
				return $this->build( 'config-version-exposure', 'WordPress version exposed in HTML meta tag', 'The WordPress version is revealed in the generator meta tag, helping attackers target known exploits.', 'low', 3.7, 'Remove the generator meta tag by adding remove_action("wp_head", "wp_generator"); to your theme.' );
			}
		}
		return null;
	}

	/** @return array|null */
	private function check_sensitive_files() {
		$config_path = ABSPATH . 'wp-config.php';
		if ( ! file_exists( $config_path ) && file_exists( dirname( ABSPATH ) . '/wp-config.php' ) ) {
			$config_path = dirname( ABSPATH ) . '/wp-config.php';
		}
		$config_dir = dirname( $config_path ) . '/';

		$files = array( 'readme.html', 'license.txt', 'wp-config.php.bak', 'wp-config.bak', '.env' );

		foreach ( $files as $file ) {
			if ( file_exists( ABSPATH . $file ) || file_exists( $config_dir . $file ) ) {
				return $this->build( 'config-sensitive-files', sprintf( 'Sensitive file accessible: %s', $file ), sprintf( 'The file "%s" was found in the webroot. Sensitive files can expose version information or credentials.', $file ), 'medium', 5.3, sprintf( 'Delete or move the file "%s" from the webroot.', $file ) );
			}
		}
		return null;
	}

	/** @return array|null */
	private function check_directory_listing() {
		$response = wp_remote_get(
			content_url( '/uploads/' ),
			array( 'timeout' => 10, 'user-agent' => 'WP Sentinel Security/' . SENTINEL_VERSION )
		);

		if ( ! is_wp_error( $response ) ) {
			$body = wp_remote_retrieve_body( $response );
			if ( false !== stripos( $body, 'Index of' ) || false !== stripos( $body, 'Parent Directory' ) ) {
				return $this->build( 'config-directory-listing', 'Directory listing is enabled', 'Directory listing is enabled on the uploads directory, exposing all uploaded files to enumeration.', 'medium', 5.3, 'Add "Options -Indexes" to your .htaccess file or configure your web server to disable directory listing.' );
			}
		}
		return null;
	}

	// -----------------------------------------------------------------------
	// Helper
	// -----------------------------------------------------------------------

	/**
	 * Build a vulnerability array.
	 *
	 * @param string $id             Vulnerability ID.
	 * @param string $title          Short title.
	 * @param string $description    Detailed description.
	 * @param string $severity       Severity level.
	 * @param float  $cvss_score     CVSS v3 score.
	 * @param string $recommendation Fix recommendation.
	 * @return array
	 */
	private function build( $id, $title, $description, $severity, $cvss_score, $recommendation ) {
		return array(
			'component_type'    => 'config',
			'component_name'    => 'WordPress Configuration',
			'component_version' => get_bloginfo( 'version' ),
			'vulnerability_id'  => $id,
			'title'             => $title,
			'description'       => $description,
			'severity'          => $severity,
			'cvss_score'        => $cvss_score,
			'cvss_vector'       => '',
			'recommendation'    => $recommendation,
			'reference_urls'    => wp_json_encode( array() ),
		);
	}
}
