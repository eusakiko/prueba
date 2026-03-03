<?php
/**
 * WordPress Security Recommendations.
 *
 * Checks the WordPress installation against a list of security best-practices
 * and returns an actionable recommendation list for the admin panel.
 *
 * Checks implemented (inspired by Sucuri's SucuriWordPressRecommendations):
 *  1.  SSL certificate active
 *  2.  PHP version is actively supported
 *  3.  WordPress core up to date
 *  4.  WordPress salt / security keys exist
 *  5.  Security keys were rotated within the last year
 *  6.  Default "admin" username does not exist
 *  7.  WP_DEBUG is disabled in production
 *  8.  DISALLOW_FILE_EDIT is defined
 *  9.  File permissions on wp-config.php are restrictive
 * 10.  Sensitive directories hardened (wp-content/uploads, wp-includes)
 * 11.  REST API XML-RPC exposure
 * 12.  Database prefix is not the default "wp_"
 * 13.  Plugin count below threshold
 * 14.  No inactive themes accumulating
 * 15.  Scheduled scans active
 *
 * @package WP_Sentinel_Security
 * @since   2.8.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Sentinel_WP_Recommendations
 */
class Sentinel_WP_Recommendations {

	/**
	 * Run all checks and return results.
	 *
	 * @return array[] Each element: { id, title, description, status, severity, fix_url }
	 *                 status: 'pass' | 'warn' | 'fail'
	 *                 severity: 'critical' | 'high' | 'medium' | 'low'
	 */
	public static function run() {
		$checks = array(
			array( __CLASS__, 'check_ssl' ),
			array( __CLASS__, 'check_php_version' ),
			array( __CLASS__, 'check_wp_version' ),
			array( __CLASS__, 'check_salt_keys_exist' ),
			array( __CLASS__, 'check_salt_keys_age' ),
			array( __CLASS__, 'check_admin_username' ),
			array( __CLASS__, 'check_wp_debug' ),
			array( __CLASS__, 'check_file_edit' ),
			array( __CLASS__, 'check_wpconfig_perms' ),
			array( __CLASS__, 'check_hardened_dirs' ),
			array( __CLASS__, 'check_xmlrpc' ),
			array( __CLASS__, 'check_db_prefix' ),
			array( __CLASS__, 'check_plugin_count' ),
			array( __CLASS__, 'check_inactive_themes' ),
			array( __CLASS__, 'check_scheduled_scan' ),
		);

		$results = array();
		foreach ( $checks as $cb ) {
			$result = call_user_func( $cb );
			if ( is_array( $result ) ) {
				$results[] = $result;
			}
		}

		// Sort: fail → warn → pass.
		usort( $results, function ( $a, $b ) {
			$order = array( 'fail' => 0, 'warn' => 1, 'pass' => 2 );
			$oa    = $order[ $a['status'] ] ?? 2;
			$ob    = $order[ $b['status'] ] ?? 2;
			if ( $oa !== $ob ) { return $oa <=> $ob; }
			// Within same status, sort by severity.
			$sev = array( 'critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3 );
			return ( $sev[ $a['severity'] ] ?? 3 ) <=> ( $sev[ $b['severity'] ] ?? 3 );
		} );

		return $results;
	}

	/**
	 * Summary counts.
	 *
	 * @return array { pass: int, warn: int, fail: int, score: int }
	 */
	public static function summary() {
		$results = self::run();
		$counts  = array( 'pass' => 0, 'warn' => 0, 'fail' => 0 );
		foreach ( $results as $r ) {
			$counts[ $r['status'] ] = ( $counts[ $r['status'] ] ?? 0 ) + 1;
		}
		$total          = count( $results );
		$counts['score'] = $total > 0 ? (int) round( $counts['pass'] / $total * 100 ) : 0;
		return $counts;
	}

	// ── Individual checks ────────────────────────────────────────────────────

	private static function check_ssl() {
		return array(
			'id'          => 'ssl',
			'title'       => __( 'SSL/TLS Certificate Active', 'wp-sentinel-security' ),
			'description' => is_ssl()
				? __( 'Your site is served over HTTPS.', 'wp-sentinel-security' )
				: __( 'Your site is not using HTTPS. SSL certificates protect data in transit between the server and visitors.', 'wp-sentinel-security' ),
			'status'      => is_ssl() ? 'pass' : 'fail',
			'severity'    => 'critical',
			'fix_url'     => 'https://wordpress.org/support/article/https-for-wordpress/',
		);
	}

	private static function check_php_version() {
		// PHP versions below 8.1 are EOL as of 2024.
		$ok = version_compare( PHP_VERSION, '8.1', '>=' );
		return array(
			'id'          => 'php_version',
			'title'       => __( 'PHP Version Is Supported', 'wp-sentinel-security' ),
			/* translators: %s: PHP version string */
			'description' => sprintf(
				$ok
					? __( 'Your PHP version (%s) is actively supported.', 'wp-sentinel-security' )
					: __( 'Your PHP version (%s) is outdated and no longer receives security updates. Upgrade to PHP 8.1+.', 'wp-sentinel-security' ),
				PHP_VERSION
			),
			'status'      => $ok ? 'pass' : 'fail',
			'severity'    => 'high',
			'fix_url'     => 'https://www.php.net/supported-versions.php',
		);
	}

	private static function check_wp_version() {
		$current = get_bloginfo( 'version' );
		$latest  = get_site_transient( 'update_core' );
		$ok      = true;
		$desc    = sprintf(
			/* translators: %s: WP version */
			__( 'WordPress %s is installed.', 'wp-sentinel-security' ),
			$current
		);

		if ( $latest && isset( $latest->updates ) ) {
			foreach ( $latest->updates as $update ) {
				if ( 'upgrade' === $update->response ) {
					$ok   = false;
					$desc = sprintf(
						/* translators: %1$s current, %2$s latest */
						__( 'WordPress %1$s is installed; version %2$s is available. Update as soon as possible.', 'wp-sentinel-security' ),
						$current,
						$update->version
					);
					break;
				}
			}
		}

		return array(
			'id'          => 'wp_version',
			'title'       => __( 'WordPress Core Is Up to Date', 'wp-sentinel-security' ),
			'description' => $desc,
			'status'      => $ok ? 'pass' : 'warn',
			'severity'    => 'high',
			'fix_url'     => admin_url( 'update-core.php' ),
		);
	}

	private static function check_salt_keys_exist() {
		$ok = defined( 'AUTH_KEY' ) && defined( 'SECURE_AUTH_KEY' )
			&& defined( 'LOGGED_IN_KEY' ) && defined( 'AUTH_SALT' );
		return array(
			'id'          => 'salt_keys',
			'title'       => __( 'WordPress Security Keys Defined', 'wp-sentinel-security' ),
			'description' => $ok
				? __( 'WordPress security keys and salts are configured.', 'wp-sentinel-security' )
				: __( 'WordPress security keys (AUTH_KEY, SECURE_AUTH_KEY, etc.) are missing in wp-config.php. Generate them at wordpress.org/support/api.', 'wp-sentinel-security' ),
			'status'      => $ok ? 'pass' : 'warn',
			'severity'    => 'medium',
			'fix_url'     => 'https://api.wordpress.org/secret-key/1.1/salt/',
		);
	}

	private static function check_salt_keys_age() {
		$wpconfig = ABSPATH . 'wp-config.php';
		if ( ! file_exists( $wpconfig ) ) {
			return null;
		}
		$modified = (int) filemtime( $wpconfig );
		$ok       = $modified > strtotime( '-12 months' );
		return array(
			'id'          => 'salt_age',
			'title'       => __( 'Security Keys Rotated in the Last Year', 'wp-sentinel-security' ),
			'description' => $ok
				? __( 'wp-config.php was modified within the last 12 months.', 'wp-sentinel-security' )
				: __( 'wp-config.php has not been modified in over a year. Rotating security keys periodically (especially after any compromise) reduces session hijacking risk.', 'wp-sentinel-security' ),
			'status'      => $ok ? 'pass' : 'warn',
			'severity'    => 'low',
			'fix_url'     => 'https://api.wordpress.org/secret-key/1.1/salt/',
		);
	}

	private static function check_admin_username() {
		$admins = get_users( array(
			'role'      => 'administrator',
			'login__in' => array( 'admin', 'administrator' ),
		) );
		$ok = empty( $admins );
		return array(
			'id'          => 'admin_username',
			'title'       => __( 'No Default "admin" Username', 'wp-sentinel-security' ),
			'description' => $ok
				? __( 'No administrator account with the username "admin" or "administrator" was found.', 'wp-sentinel-security' )
				: __( 'An administrator account with the username "admin" or "administrator" exists. Rename it to reduce brute-force attack surface.', 'wp-sentinel-security' ),
			'status'      => $ok ? 'pass' : 'warn',
			'severity'    => 'high',
			'fix_url'     => admin_url( 'users.php' ),
		);
	}

	private static function check_wp_debug() {
		$ok = ! ( defined( 'WP_DEBUG' ) && WP_DEBUG );
		return array(
			'id'          => 'wp_debug',
			'title'       => __( 'WP_DEBUG Is Disabled', 'wp-sentinel-security' ),
			'description' => $ok
				? __( 'WP_DEBUG is disabled — PHP errors are not exposed to visitors.', 'wp-sentinel-security' )
				: __( 'WP_DEBUG is enabled. This exposes PHP errors and notices to all visitors, potentially leaking sensitive information. Disable it in wp-config.php.', 'wp-sentinel-security' ),
			'status'      => $ok ? 'pass' : 'fail',
			'severity'    => 'high',
			'fix_url'     => 'https://wordpress.org/support/article/debugging-in-wordpress/',
		);
	}

	private static function check_file_edit() {
		$ok = defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT;
		return array(
			'id'          => 'file_edit',
			'title'       => __( 'File Editing Disabled (DISALLOW_FILE_EDIT)', 'wp-sentinel-security' ),
			'description' => $ok
				? __( 'DISALLOW_FILE_EDIT is set — the WordPress theme/plugin editor is disabled.', 'wp-sentinel-security' )
				: __( 'DISALLOW_FILE_EDIT is not set. Adding "define(\'DISALLOW_FILE_EDIT\', true);" to wp-config.php prevents attackers from modifying files through the WordPress backend.', 'wp-sentinel-security' ),
			'status'      => $ok ? 'pass' : 'warn',
			'severity'    => 'medium',
			'fix_url'     => 'https://wordpress.org/support/article/editing-wp-config-php/#disable-the-plugin-and-theme-file-editor',
		);
	}

	private static function check_wpconfig_perms() {
		$wpconfig = ABSPATH . 'wp-config.php';
		if ( ! file_exists( $wpconfig ) ) {
			return null;
		}
		$perms = (int) substr( sprintf( '%o', fileperms( $wpconfig ) ), -4 );
		$ok    = $perms <= 640;
		return array(
			'id'          => 'wpconfig_perms',
			/* translators: %s: file permission octal */
			'title'       => __( 'wp-config.php Has Restrictive Permissions', 'wp-sentinel-security' ),
			'description' => sprintf(
				$ok
					? __( 'wp-config.php permissions are %s (secure).', 'wp-sentinel-security' )
					: __( 'wp-config.php permissions are %s — should be 600 or 640 to restrict read access.', 'wp-sentinel-security' ),
				$perms
			),
			'status'      => $ok ? 'pass' : 'warn',
			'severity'    => 'high',
			'fix_url'     => 'https://wordpress.org/support/article/changing-file-permissions/',
		);
	}

	private static function check_hardened_dirs() {
		$dirs_to_check = array(
			WP_CONTENT_DIR . '/uploads',
			ABSPATH . WPINC,
		);
		$unhardened = array();
		foreach ( $dirs_to_check as $dir ) {
			if ( ! is_dir( $dir ) ) { continue; }
			$htaccess = rtrim( $dir, '/' ) . '/.htaccess';
			if ( ! file_exists( $htaccess ) ) {
				$unhardened[] = str_replace( ABSPATH, '', $dir );
				continue;
			}
			$content = (string) file_get_contents( $htaccess ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
			if ( false === strpos( $content, 'FilesMatch' ) && false === strpos( $content, 'php' ) ) {
				$unhardened[] = str_replace( ABSPATH, '', $dir );
			}
		}
		$ok = empty( $unhardened );
		return array(
			'id'          => 'hardened_dirs',
			'title'       => __( 'Sensitive Directories Hardened', 'wp-sentinel-security' ),
			'description' => $ok
				? __( 'wp-content/uploads and wp-includes have PHP-execution restrictions.', 'wp-sentinel-security' )
				: sprintf(
					/* translators: %s: comma-separated directory list */
					__( 'The following directories are not hardened against direct PHP execution: %s. Use Sentinel → Hardening to apply .htaccess rules.', 'wp-sentinel-security' ),
					implode( ', ', $unhardened )
				  ),
			'status'      => $ok ? 'pass' : 'warn',
			'severity'    => 'high',
			'fix_url'     => admin_url( 'admin.php?page=sentinel-hardening' ),
		);
	}

	private static function check_xmlrpc() {
		// Check if XML-RPC is enabled (default in WP; many attack vectors).
		$enabled = (bool) apply_filters( 'xmlrpc_enabled', true );
		return array(
			'id'          => 'xmlrpc',
			'title'       => __( 'XML-RPC Exposure', 'wp-sentinel-security' ),
			'description' => ! $enabled
				? __( 'XML-RPC is disabled.', 'wp-sentinel-security' )
				: __( 'XML-RPC is enabled. Unless you use Jetpack or mobile apps that need it, consider disabling it to reduce attack surface (brute-force, DDoS amplification).', 'wp-sentinel-security' ),
			'status'      => ! $enabled ? 'pass' : 'warn',
			'severity'    => 'medium',
			'fix_url'     => 'https://wordpress.org/support/article/hardening-wordpress/#security-through-obscurity',
		);
	}

	private static function check_db_prefix() {
		global $wpdb;
		$ok = ( 'wp_' !== $wpdb->prefix );
		return array(
			'id'          => 'db_prefix',
			'title'       => __( 'Database Prefix Changed From Default', 'wp-sentinel-security' ),
			/* translators: %s: DB prefix */
			'description' => sprintf(
				$ok
					? __( 'Database prefix is "%s" (non-default — good).', 'wp-sentinel-security' )
					: __( 'Database prefix is the default "wp_". Using a unique prefix reduces the risk from SQL injection attacks that guess table names.', 'wp-sentinel-security' ),
				esc_html( $wpdb->prefix )
			),
			'status'      => $ok ? 'pass' : 'warn',
			'severity'    => 'low',
			'fix_url'     => 'https://wordpress.org/support/article/hardening-wordpress/',
		);
	}

	private static function check_plugin_count() {
		$active  = (array) get_option( 'active_plugins', array() );
		$count   = count( $active );
		$limit   = 30;
		$ok      = $count <= $limit;
		return array(
			'id'          => 'plugin_count',
			/* translators: %d: plugin count */
			'title'       => __( 'Plugin Count Within Recommended Limit', 'wp-sentinel-security' ),
			'description' => sprintf(
				$ok
					? __( 'You have %d active plugins (within the recommended limit of 30).', 'wp-sentinel-security' )
					: __( 'You have %d active plugins. The more plugins installed, the greater the attack surface. Review and deactivate plugins you don\'t actively use.', 'wp-sentinel-security' ),
				$count
			),
			'status'      => $ok ? 'pass' : 'warn',
			'severity'    => 'low',
			'fix_url'     => admin_url( 'plugins.php' ),
		);
	}

	private static function check_inactive_themes() {
		$themes   = wp_get_themes();
		$active   = get_stylesheet();
		$inactive = array_filter( array_keys( $themes ), function ( $t ) use ( $active ) {
			return $t !== $active;
		} );
		$count    = count( $inactive );
		$ok       = $count <= 2; // Keep 1 default fallback.
		return array(
			'id'          => 'inactive_themes',
			'title'       => __( 'Inactive Themes Removed', 'wp-sentinel-security' ),
			'description' => $ok
				? __( 'You have few inactive themes installed — good.', 'wp-sentinel-security' )
				: sprintf(
					/* translators: %d: theme count */
					__( 'You have %d inactive themes. Unused themes may contain vulnerabilities. Remove themes you are not using.', 'wp-sentinel-security' ),
					$count
				  ),
			'status'      => $ok ? 'pass' : 'warn',
			'severity'    => 'low',
			'fix_url'     => admin_url( 'themes.php' ),
		);
	}

	private static function check_scheduled_scan() {
		$ok = (bool) wp_next_scheduled( 'sentinel_scheduled_scan' );
		return array(
			'id'          => 'scheduled_scan',
			'title'       => __( 'Scheduled Security Scan Active', 'wp-sentinel-security' ),
			'description' => $ok
				? __( 'A Sentinel scheduled scan is configured and will run automatically.', 'wp-sentinel-security' )
				: __( 'No scheduled security scan is configured. Enable automatic scanning in Sentinel → Settings to catch threats without manual intervention.', 'wp-sentinel-security' ),
			'status'      => $ok ? 'pass' : 'warn',
			'severity'    => 'medium',
			'fix_url'     => admin_url( 'admin.php?page=sentinel-settings' ),
		);
	}
}
