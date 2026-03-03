<?php
/**
 * File Hardening — Handles filesystem-level security hardening checks.
 *
 * Covers: file editing lockdown, PHP execution blocking in uploads,
 * wp-config.php & .htaccess permission tightening, directory listing
 * prevention, and HTTP security headers injection.
 *
 * @package WP_Sentinel_Security
 * @since   2.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class File_Hardening
 *
 * Each public group exposes three methods per check:
 *   apply_*()  — activate the hardening measure
 *   revert_*() — undo the hardening measure
 *   status_*() — report current state as an array with 'status' and 'details' keys
 *
 * Status values: 'applied' | 'not_applied' | 'partial'
 */
class File_Hardening {

	/**
	 * Absolute path to the root .htaccess file.
	 *
	 * @var string
	 */
	private $htaccess_path;

	/**
	 * Absolute path to the uploads directory .htaccess file.
	 *
	 * @var string
	 */
	private $uploads_htaccess_path;

	/**
	 * Absolute path to wp-config.php.
	 *
	 * @var string
	 */
	private $wp_config_path;

	/**
	 * Sentinel marker used to wrap inserted .htaccess blocks.
	 *
	 * @var string
	 */
	const HTACCESS_MARKER = 'WP Sentinel Security';

	/**
	 * Constructor — resolve paths.
	 */
	public function __construct() {
		$upload_dir                  = wp_upload_dir();
		$this->htaccess_path         = ABSPATH . '.htaccess';
		$this->uploads_htaccess_path = trailingslashit( $upload_dir['basedir'] ) . '.htaccess';
		$this->wp_config_path        = ABSPATH . 'wp-config.php';
	}

	// =========================================================================
	// 1. Disable file editing (DISALLOW_FILE_EDIT via wp-config.php)
	// =========================================================================

	/**
	 * Apply: disable the theme/plugin file editor via DISALLOW_FILE_EDIT.
	 *
	 * @return array{status: string, message: string}
	 */
	public function disable_file_editing() {
		if ( defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT ) {
			return array(
				'status'  => 'already_applied',
				'message' => __( 'DISALLOW_FILE_EDIT is already defined (possibly in wp-config.php).', 'wp-sentinel-security' ),
			);
		}

		$result = $this->add_wp_config_constant( 'DISALLOW_FILE_EDIT', 'true' );
		if ( $result ) {
			return array(
				'status'  => 'applied',
				'message' => __( 'File editing has been disabled.', 'wp-sentinel-security' ),
			);
		}

		return array(
			'status'  => 'error',
			'message' => __( 'Could not write to wp-config.php. Check file permissions.', 'wp-sentinel-security' ),
		);
	}

	/**
	 * Revert: re-enable the theme/plugin file editor.
	 *
	 * @return array{status: string, message: string}
	 */
	public function revert_disable_file_editing() {
		$result = $this->remove_wp_config_constant( 'DISALLOW_FILE_EDIT' );
		if ( $result ) {
			return array(
				'status'  => 'reverted',
				'message' => __( 'File editing restriction has been removed.', 'wp-sentinel-security' ),
			);
		}
		return array(
			'status'  => 'error',
			'message' => __( 'Could not update wp-config.php. Check file permissions.', 'wp-sentinel-security' ),
		);
	}

	/**
	 * Status: check whether DISALLOW_FILE_EDIT is active.
	 *
	 * @return array{status: string, details: string}
	 */
	public function status_disable_file_editing() {
		$in_config = $this->wp_config_has_constant( 'DISALLOW_FILE_EDIT' );
		$runtime   = defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT;

		if ( $in_config && $runtime ) {
			return array(
				'status'  => 'applied',
				'details' => __( 'DISALLOW_FILE_EDIT is defined in wp-config.php and active.', 'wp-sentinel-security' ),
			);
		}

		if ( $runtime ) {
			return array(
				'status'  => 'partial',
				'details' => __( 'DISALLOW_FILE_EDIT is active at runtime but not set in wp-config.php by Sentinel.', 'wp-sentinel-security' ),
			);
		}

		return array(
			'status'  => 'not_applied',
			'details' => __( 'File editing is currently enabled.', 'wp-sentinel-security' ),
		);
	}

	// =========================================================================
	// 2. Block PHP execution in uploads directory
	// =========================================================================

	/**
	 * Apply: drop a .htaccess in the uploads dir that denies PHP execution.
	 *
	 * @return array{status: string, message: string}
	 */
	public function block_php_uploads() {
		$rules = array(
			'<FilesMatch "\.(?:php|php[0-9]+|phtml|phar)$">',
			'    <IfModule mod_authz_core.c>',
			'        Require all denied',
			'    </IfModule>',
			'    <IfModule !mod_authz_core.c>',
			'        Order allow,deny',
			'        Deny from all',
			'    </IfModule>',
			'</FilesMatch>',
		);

		$result = $this->write_htaccess_marker( $this->uploads_htaccess_path, $rules );
		if ( $result ) {
			return array(
				'status'  => 'applied',
				'message' => __( 'PHP execution in uploads directory has been blocked.', 'wp-sentinel-security' ),
			);
		}
		return array(
			'status'  => 'error',
			'message' => __( 'Could not write to uploads .htaccess. Check file permissions.', 'wp-sentinel-security' ),
		);
	}

	/**
	 * Revert: remove the PHP-blocking .htaccess rule from uploads.
	 *
	 * @return array{status: string, message: string}
	 */
	public function revert_block_php_uploads() {
		$result = $this->remove_htaccess_marker( $this->uploads_htaccess_path );
		if ( $result ) {
			return array(
				'status'  => 'reverted',
				'message' => __( 'PHP execution block in uploads has been removed.', 'wp-sentinel-security' ),
			);
		}
		return array(
			'status'  => 'error',
			'message' => __( 'Could not update uploads .htaccess. Check file permissions.', 'wp-sentinel-security' ),
		);
	}

	/**
	 * Status: check whether PHP execution is blocked in uploads.
	 *
	 * @return array{status: string, details: string}
	 */
	public function status_block_php_uploads() {
		if ( ! file_exists( $this->uploads_htaccess_path ) ) {
			return array(
				'status'  => 'not_applied',
				'details' => __( 'No .htaccess found in uploads directory.', 'wp-sentinel-security' ),
			);
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$contents = file_get_contents( $this->uploads_htaccess_path );
		if ( false !== strpos( $contents, '# BEGIN ' . self::HTACCESS_MARKER ) ) {
			return array(
				'status'  => 'applied',
				'details' => __( 'PHP execution is blocked in the uploads directory.', 'wp-sentinel-security' ),
			);
		}

		return array(
			'status'  => 'not_applied',
			'details' => __( 'PHP execution is not blocked in the uploads directory.', 'wp-sentinel-security' ),
		);
	}

	// =========================================================================
	// 3. Protect wp-config.php (permissions 0440 or stricter)
	// =========================================================================

	/**
	 * Apply: tighten wp-config.php file permissions to 0440.
	 *
	 * @return array{status: string, message: string}
	 */
	public function protect_wp_config() {
		if ( ! file_exists( $this->wp_config_path ) ) {
			return array(
				'status'  => 'error',
				'message' => __( 'wp-config.php not found.', 'wp-sentinel-security' ),
			);
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod
		if ( chmod( $this->wp_config_path, 0440 ) ) {
			return array(
				'status'  => 'applied',
				'message' => __( 'wp-config.php permissions set to 0440.', 'wp-sentinel-security' ),
			);
		}

		return array(
			'status'  => 'error',
			'message' => __( 'Could not change wp-config.php permissions.', 'wp-sentinel-security' ),
		);
	}

	/**
	 * Revert: restore wp-config.php permissions to 0644.
	 *
	 * @return array{status: string, message: string}
	 */
	public function revert_protect_wp_config() {
		if ( ! file_exists( $this->wp_config_path ) ) {
			return array(
				'status'  => 'error',
				'message' => __( 'wp-config.php not found.', 'wp-sentinel-security' ),
			);
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod
		if ( chmod( $this->wp_config_path, 0644 ) ) {
			return array(
				'status'  => 'reverted',
				'message' => __( 'wp-config.php permissions restored to 0644.', 'wp-sentinel-security' ),
			);
		}

		return array(
			'status'  => 'error',
			'message' => __( 'Could not restore wp-config.php permissions.', 'wp-sentinel-security' ),
		);
	}

	/**
	 * Status: check wp-config.php permission level.
	 *
	 * @return array{status: string, details: string}
	 */
	public function status_protect_wp_config() {
		if ( ! file_exists( $this->wp_config_path ) ) {
			return array(
				'status'  => 'not_applied',
				'details' => __( 'wp-config.php not found.', 'wp-sentinel-security' ),
			);
		}

		// fileperms() returns a 16-bit value; mask with 0777 to get permission bits.
		$perms = fileperms( $this->wp_config_path ) & 0777;

		if ( $perms <= 0440 ) {
			return array(
				'status'  => 'applied',
				/* translators: %s: octal permission string */
				'details' => sprintf( __( 'wp-config.php permissions are %s (secure).', 'wp-sentinel-security' ), decoct( $perms ) ),
			);
		}

		if ( $perms <= 0640 ) {
			return array(
				'status'  => 'partial',
				/* translators: %s: octal permission string */
				'details' => sprintf( __( 'wp-config.php permissions are %s. Recommend 0440.', 'wp-sentinel-security' ), decoct( $perms ) ),
			);
		}

		return array(
			'status'  => 'not_applied',
			/* translators: %s: octal permission string */
			'details' => sprintf( __( 'wp-config.php permissions are %s (too permissive).', 'wp-sentinel-security' ), decoct( $perms ) ),
		);
	}

	// =========================================================================
	// 4. Protect .htaccess (permissions check)
	// =========================================================================

	/**
	 * Apply: tighten root .htaccess permissions to 0444.
	 *
	 * @return array{status: string, message: string}
	 */
	public function protect_htaccess() {
		if ( ! file_exists( $this->htaccess_path ) ) {
			return array(
				'status'  => 'error',
				'message' => __( '.htaccess not found at WordPress root.', 'wp-sentinel-security' ),
			);
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod
		if ( chmod( $this->htaccess_path, 0444 ) ) {
			return array(
				'status'  => 'applied',
				'message' => __( '.htaccess permissions set to 0444 (read-only).', 'wp-sentinel-security' ),
			);
		}

		return array(
			'status'  => 'error',
			'message' => __( 'Could not change .htaccess permissions.', 'wp-sentinel-security' ),
		);
	}

	/**
	 * Revert: restore root .htaccess permissions to 0644.
	 *
	 * @return array{status: string, message: string}
	 */
	public function revert_protect_htaccess() {
		if ( ! file_exists( $this->htaccess_path ) ) {
			return array(
				'status'  => 'error',
				'message' => __( '.htaccess not found at WordPress root.', 'wp-sentinel-security' ),
			);
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod
		if ( chmod( $this->htaccess_path, 0644 ) ) {
			return array(
				'status'  => 'reverted',
				'message' => __( '.htaccess permissions restored to 0644.', 'wp-sentinel-security' ),
			);
		}

		return array(
			'status'  => 'error',
			'message' => __( 'Could not restore .htaccess permissions.', 'wp-sentinel-security' ),
		);
	}

	/**
	 * Status: check root .htaccess permission level.
	 *
	 * @return array{status: string, details: string}
	 */
	public function status_protect_htaccess() {
		if ( ! file_exists( $this->htaccess_path ) ) {
			return array(
				'status'  => 'not_applied',
				'details' => __( '.htaccess not found at WordPress root.', 'wp-sentinel-security' ),
			);
		}

		$perms = fileperms( $this->htaccess_path ) & 0777;

		if ( $perms <= 0444 ) {
			return array(
				'status'  => 'applied',
				/* translators: %s: octal permission string */
				'details' => sprintf( __( '.htaccess permissions are %s (secure).', 'wp-sentinel-security' ), decoct( $perms ) ),
			);
		}

		if ( $perms <= 0644 ) {
			return array(
				'status'  => 'partial',
				/* translators: %s: octal permission string */
				'details' => sprintf( __( '.htaccess permissions are %s. Recommend 0444.', 'wp-sentinel-security' ), decoct( $perms ) ),
			);
		}

		return array(
			'status'  => 'not_applied',
			/* translators: %s: octal permission string */
			'details' => sprintf( __( '.htaccess permissions are %s (too permissive).', 'wp-sentinel-security' ), decoct( $perms ) ),
		);
	}

	// =========================================================================
	// 5. Disable directory listing
	// =========================================================================

	/**
	 * Apply: add "Options -Indexes" to root .htaccess via Sentinel marker.
	 *
	 * @return array{status: string, message: string}
	 */
	public function disable_directory_listing() {
		$rules  = array( 'Options -Indexes' );
		$result = $this->write_htaccess_marker( $this->htaccess_path, $rules, 'Sentinel-No-Directory-Listing' );
		if ( $result ) {
			return array(
				'status'  => 'applied',
				'message' => __( 'Directory listing has been disabled.', 'wp-sentinel-security' ),
			);
		}
		return array(
			'status'  => 'error',
			'message' => __( 'Could not write to .htaccess. Check file permissions.', 'wp-sentinel-security' ),
		);
	}

	/**
	 * Revert: remove "Options -Indexes" marker from root .htaccess.
	 *
	 * @return array{status: string, message: string}
	 */
	public function revert_disable_directory_listing() {
		$result = $this->remove_htaccess_marker( $this->htaccess_path, 'Sentinel-No-Directory-Listing' );
		if ( $result ) {
			return array(
				'status'  => 'reverted',
				'message' => __( 'Directory listing restriction has been removed.', 'wp-sentinel-security' ),
			);
		}
		return array(
			'status'  => 'error',
			'message' => __( 'Could not update .htaccess. Check file permissions.', 'wp-sentinel-security' ),
		);
	}

	/**
	 * Status: check whether directory listing is disabled.
	 *
	 * @return array{status: string, details: string}
	 */
	public function status_disable_directory_listing() {
		if ( ! file_exists( $this->htaccess_path ) ) {
			return array(
				'status'  => 'not_applied',
				'details' => __( '.htaccess not found at WordPress root.', 'wp-sentinel-security' ),
			);
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$contents = file_get_contents( $this->htaccess_path );

		if ( false !== strpos( $contents, '# BEGIN Sentinel-No-Directory-Listing' ) ) {
			return array(
				'status'  => 'applied',
				'details' => __( 'Directory listing is disabled (Options -Indexes is set by Sentinel).', 'wp-sentinel-security' ),
			);
		}

		if ( false !== strpos( $contents, 'Options -Indexes' ) ) {
			return array(
				'status'  => 'partial',
				'details' => __( '"Options -Indexes" present but not managed by Sentinel.', 'wp-sentinel-security' ),
			);
		}

		return array(
			'status'  => 'not_applied',
			'details' => __( 'Directory listing is currently enabled.', 'wp-sentinel-security' ),
		);
	}

	// =========================================================================
	// 6. Security headers via .htaccess
	// =========================================================================

	/**
	 * Apply: inject HTTP security response headers into root .htaccess.
	 *
	 * Headers added:
	 *   X-Content-Type-Options, X-Frame-Options, Referrer-Policy,
	 *   X-XSS-Protection, Permissions-Policy, Content-Security-Policy.
	 *
	 * @return array{status: string, message: string}
	 */
	public function add_security_headers() {
		$rules = array(
			'<IfModule mod_headers.c>',
			'    Header always set X-Content-Type-Options "nosniff"',
			'    Header always set X-Frame-Options "SAMEORIGIN"',
			'    Header always set Referrer-Policy "strict-origin-when-cross-origin"',
			'    Header always set X-XSS-Protection "1; mode=block"',
			'    Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"',
			'    Header always set Content-Security-Policy "default-src \'self\'; script-src \'self\' \'unsafe-inline\'; style-src \'self\' \'unsafe-inline\';"',
			'</IfModule>',
		);

		$result = $this->write_htaccess_marker( $this->htaccess_path, $rules, 'Sentinel-Security-Headers' );
		if ( $result ) {
			return array(
				'status'  => 'applied',
				'message' => __( 'HTTP security headers have been added.', 'wp-sentinel-security' ),
			);
		}
		return array(
			'status'  => 'error',
			'message' => __( 'Could not write security headers to .htaccess.', 'wp-sentinel-security' ),
		);
	}

	/**
	 * Revert: remove security headers marker from root .htaccess.
	 *
	 * @return array{status: string, message: string}
	 */
	public function revert_add_security_headers() {
		$result = $this->remove_htaccess_marker( $this->htaccess_path, 'Sentinel-Security-Headers' );
		if ( $result ) {
			return array(
				'status'  => 'reverted',
				'message' => __( 'Security headers have been removed from .htaccess.', 'wp-sentinel-security' ),
			);
		}
		return array(
			'status'  => 'error',
			'message' => __( 'Could not update .htaccess. Check file permissions.', 'wp-sentinel-security' ),
		);
	}

	/**
	 * Status: check whether Sentinel security headers are in place.
	 *
	 * @return array{status: string, details: string}
	 */
	public function status_add_security_headers() {
		if ( ! file_exists( $this->htaccess_path ) ) {
			return array(
				'status'  => 'not_applied',
				'details' => __( '.htaccess not found at WordPress root.', 'wp-sentinel-security' ),
			);
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$contents = file_get_contents( $this->htaccess_path );

		if ( false !== strpos( $contents, '# BEGIN Sentinel-Security-Headers' ) ) {
			return array(
				'status'  => 'applied',
				'details' => __( 'HTTP security headers are active (managed by Sentinel).', 'wp-sentinel-security' ),
			);
		}

		if ( false !== strpos( $contents, 'X-Content-Type-Options' ) ) {
			return array(
				'status'  => 'partial',
				'details' => __( 'Some security headers are present but not all are managed by Sentinel.', 'wp-sentinel-security' ),
			);
		}

		return array(
			'status'  => 'not_applied',
			'details' => __( 'HTTP security headers are not configured.', 'wp-sentinel-security' ),
		);
	}

	// =========================================================================
	// Private helpers
	// =========================================================================

	/**
	 * Write a block of .htaccess rules wrapped in Sentinel marker comments.
	 *
	 * If a marker block already exists it is replaced; otherwise it is
	 * prepended to the file (or the file is created).
	 *
	 * @param string   $htaccess_file Absolute path to the .htaccess file.
	 * @param string[] $rules         Array of rule lines (no trailing newline needed).
	 * @param string   $marker        Unique marker label (default: self::HTACCESS_MARKER).
	 * @return bool True on success, false on failure.
	 */
	private function write_htaccess_marker( $htaccess_file, array $rules, $marker = self::HTACCESS_MARKER ) {
		$existing = '';
		if ( file_exists( $htaccess_file ) ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
			$existing = file_get_contents( $htaccess_file );
			if ( false === $existing ) {
				return false;
			}
		}

		$begin_marker = '# BEGIN ' . $marker;
		$end_marker   = '# END ' . $marker;

		// Remove any existing block for this marker.
		$pattern  = '/# BEGIN ' . preg_quote( $marker, '/' ) . '.*?# END ' . preg_quote( $marker, '/' ) . '\n?/s';
		$existing = preg_replace( $pattern, '', $existing );
		$existing = ltrim( $existing );

		$block  = $begin_marker . "\n";
		$block .= implode( "\n", $rules ) . "\n";
		$block .= $end_marker . "\n\n";

		$new_contents = $block . $existing;

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		return false !== file_put_contents( $htaccess_file, $new_contents );
	}

	/**
	 * Remove a Sentinel-managed marker block from an .htaccess file.
	 *
	 * @param string $htaccess_file Absolute path to the .htaccess file.
	 * @param string $marker        Marker label to remove (default: self::HTACCESS_MARKER).
	 * @return bool True on success (or if file/marker did not exist), false on write failure.
	 */
	private function remove_htaccess_marker( $htaccess_file, $marker = self::HTACCESS_MARKER ) {
		if ( ! file_exists( $htaccess_file ) ) {
			return true; // Nothing to remove.
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$contents = file_get_contents( $htaccess_file );
		if ( false === $contents ) {
			return false;
		}

		$pattern  = '/# BEGIN ' . preg_quote( $marker, '/' ) . '.*?# END ' . preg_quote( $marker, '/' ) . '\n?/s';
		$new_contents = preg_replace( $pattern, '', $contents );

		if ( $new_contents === $contents ) {
			return true; // Marker was not present; nothing to do.
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		return false !== file_put_contents( $htaccess_file, $new_contents );
	}

	/**
	 * Add a define() constant to wp-config.php before the stop-editing marker.
	 *
	 * Creates a backup at wp-config.php.sentinel-bak before any modification.
	 *
	 * @param string $constant Constant name (e.g. 'DISALLOW_FILE_EDIT').
	 * @param string $value    Raw PHP value to write (e.g. 'true', "'my-string'").
	 * @return bool True on success, false on failure.
	 */
	private function add_wp_config_constant( $constant, $value ) {
		if ( ! file_exists( $this->wp_config_path ) || ! is_writable( $this->wp_config_path ) ) {
			return false;
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$contents = file_get_contents( $this->wp_config_path );
		if ( false === $contents ) {
			return false;
		}

		// Bail if constant is already defined.
		if ( preg_match( '/define\s*\(\s*[\'"]' . preg_quote( $constant, '/' ) . '[\'"]/', $contents ) ) {
			return true;
		}

		// Backup before modifying.
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		file_put_contents( $this->wp_config_path . '.sentinel-bak', $contents );

		$new_line    = "define( '" . $constant . "', " . $value . " ); // Added by WP Sentinel Security\n";
		$stop_marker = "/* That's all, stop editing!";
		$new_contents = str_replace( $stop_marker, $new_line . $stop_marker, $contents );

		if ( $new_contents === $contents ) {
			// Fallback: append before closing PHP tag or at end.
			$new_contents = $contents . "\n" . $new_line;
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		return false !== file_put_contents( $this->wp_config_path, $new_contents );
	}

	/**
	 * Remove a Sentinel-added define() constant from wp-config.php.
	 *
	 * Only removes lines that end with the Sentinel comment marker.
	 *
	 * @param string $constant Constant name to remove.
	 * @return bool True on success, false on failure.
	 */
	private function remove_wp_config_constant( $constant ) {
		if ( ! file_exists( $this->wp_config_path ) || ! is_writable( $this->wp_config_path ) ) {
			return false;
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$contents = file_get_contents( $this->wp_config_path );
		if ( false === $contents ) {
			return false;
		}

		$pattern      = '/^[^\S\r\n]*define\s*\(\s*[\'"]' . preg_quote( $constant, '/' ) . '[\'"].*Added by WP Sentinel Security.*\n?/m';
		$new_contents = preg_replace( $pattern, '', $contents );

		if ( $new_contents === $contents ) {
			return true; // Nothing to remove.
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		return false !== file_put_contents( $this->wp_config_path, $new_contents );
	}

	/**
	 * Check whether wp-config.php contains a Sentinel-managed constant definition.
	 *
	 * @param string $constant Constant name to search for.
	 * @return bool True if the Sentinel-added line is found.
	 */
	private function wp_config_has_constant( $constant ) {
		if ( ! file_exists( $this->wp_config_path ) ) {
			return false;
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$contents = file_get_contents( $this->wp_config_path );
		if ( false === $contents ) {
			return false;
		}

		$pattern = '/define\s*\(\s*[\'"]' . preg_quote( $constant, '/' ) . '[\'"].*Added by WP Sentinel Security/';
		return (bool) preg_match( $pattern, $contents );
	}

	// =========================================================================
	// 7. .htaccess PHP-deny hardening (Sucuri-style)
	//
	// Writes a FilesMatch block that denies direct HTTP access to PHP files
	// inside a given directory. Supports both Apache 2.2 (Order/Deny) and
	// Apache 2.4+ (Require). Works for any directory that has or can have
	// an .htaccess file, but is most commonly used for:
	//   • wp-content/uploads
	//   • wp-includes
	//
	// The block is surrounded by Sentinel markers so it can be cleanly removed.
	// =========================================================================

	/**
	 * The PHP-deny .htaccess block (Apache 2.2 + 2.4 compatible).
	 * Case-insensitive match covers .php, .PHP, .Php, .pHp5, etc.
	 *
	 * @return string[]
	 */
	private static function php_deny_rules() {
		return array(
			'<FilesMatch "\\.(?i:php)$">',
			'  <IfModule !mod_authz_core.c>',
			'    Order allow,deny',
			'    Deny from all',
			'  </IfModule>',
			'  <IfModule mod_authz_core.c>',
			'    Require all denied',
			'  </IfModule>',
			'</FilesMatch>',
		);
	}

	/**
	 * Return the full .htaccess path for a given directory.
	 *
	 * @param string $directory Absolute directory path.
	 * @return string
	 */
	public static function htaccess_path( $directory ) {
		return rtrim( $directory, '/\\' ) . DIRECTORY_SEPARATOR . '.htaccess';
	}

	/**
	 * Apply PHP-deny rules to a directory by writing/appending to its .htaccess.
	 * Idempotent — does nothing if the rules are already present.
	 *
	 * @param string $directory Absolute path to the directory to harden.
	 * @return array{status: string, message: string}
	 */
	public function harden_directory( $directory ) {
		$directory = rtrim( (string) $directory, '/\\' );

		if ( ! is_dir( $directory ) ) {
			return array( 'status' => 'error', 'message' => __( 'Directory does not exist.', 'wp-sentinel-security' ) );
		}

		// Only supported on Apache; skip gracefully on Nginx/IIS.
		if ( $this->is_nginx() || $this->is_iis() ) {
			return array( 'status' => 'error', 'message' => __( '.htaccess hardening is only supported on Apache servers.', 'wp-sentinel-security' ) );
		}

		$htaccess  = self::htaccess_path( $directory );
		$rules_str = implode( "\n", self::php_deny_rules() );

		// Already hardened?
		if ( file_exists( $htaccess ) ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
			$existing = (string) file_get_contents( $htaccess );
			if ( false !== strpos( $existing, $rules_str ) ) {
				return array( 'status' => 'already_applied', 'message' => __( 'Directory is already hardened.', 'wp-sentinel-security' ) );
			}
			// Remove any old-style rules left by older plugin versions.
			$old_rule = "<Files *.php>\ndeny from all\n</Files>";
			if ( false !== strpos( $existing, $old_rule ) ) {
				$existing = str_replace( $old_rule, '', $existing );
				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
				file_put_contents( $htaccess, $existing );
			}
		}

		if ( ! is_writable( $directory ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable
			return array( 'status' => 'error', 'message' => __( 'Directory is not writable.', 'wp-sentinel-security' ) );
		}

		$block = "\n# BEGIN WP Sentinel Security PHP Hardening\n" . $rules_str . "\n# END WP Sentinel Security PHP Hardening\n";

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		$written = file_put_contents( $htaccess, $block, FILE_APPEND );
		if ( false === $written ) {
			return array( 'status' => 'error', 'message' => __( 'Could not write to .htaccess.', 'wp-sentinel-security' ) );
		}

		return array( 'status' => 'applied', 'message' => __( 'PHP-deny rules applied to directory.', 'wp-sentinel-security' ) );
	}

	/**
	 * Remove PHP-deny rules from a directory's .htaccess.
	 *
	 * @param string $directory Absolute path.
	 * @return array{status: string, message: string}
	 */
	public function unharden_directory( $directory ) {
		$htaccess = self::htaccess_path( rtrim( (string) $directory, '/\\' ) );
		if ( ! file_exists( $htaccess ) ) {
			return array( 'status' => 'not_applied', 'message' => __( 'No .htaccess file found — directory is not hardened.', 'wp-sentinel-security' ) );
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$content   = (string) file_get_contents( $htaccess );
		$rules_str = implode( "\n", self::php_deny_rules() );

		// Remove the Sentinel-wrapped block.
		$content = preg_replace( '/\n?# BEGIN WP Sentinel Security PHP Hardening\n.*?# END WP Sentinel Security PHP Hardening\n?/s', '', $content );
		// Also strip bare rules without the wrapper (legacy).
		$content = str_replace( $rules_str, '', $content );

		$trimmed = trim( $content );

		// Delete the file if it is now empty.
		if ( '' === $trimmed ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
			@unlink( $htaccess );
			return array( 'status' => 'reverted', 'message' => __( 'PHP-deny rules removed (.htaccess deleted — it was empty).', 'wp-sentinel-security' ) );
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		file_put_contents( $htaccess, $content );
		return array( 'status' => 'reverted', 'message' => __( 'PHP-deny rules removed from .htaccess.', 'wp-sentinel-security' ) );
	}

	/**
	 * Check whether a directory has PHP-deny rules in its .htaccess.
	 *
	 * @param string $directory Absolute path.
	 * @return bool
	 */
	public function is_directory_hardened( $directory ) {
		$htaccess = self::htaccess_path( rtrim( (string) $directory, '/\\' ) );
		if ( ! file_exists( $htaccess ) ) {
			return false;
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$content = (string) file_get_contents( $htaccess );
		return false !== strpos( $content, implode( "\n", self::php_deny_rules() ) );
	}

	/**
	 * Get the list of directories that can/should be hardened and their current status.
	 *
	 * @return array[] Each: { directory, label, hardened: bool, writable: bool }
	 */
	public function get_hardenable_directories() {
		$upload_dir = wp_upload_dir();
		$dirs = array(
			array(
				'directory' => WP_CONTENT_DIR . '/uploads',
				'label'     => 'wp-content/uploads',
			),
			array(
				'directory' => ABSPATH . WPINC,
				'label'     => 'wp-includes',
			),
			array(
				'directory' => WP_CONTENT_DIR,
				'label'     => 'wp-content',
			),
		);

		$result = array();
		foreach ( $dirs as $item ) {
			$dir = $item['directory'];
			$result[] = array(
				'directory' => $dir,
				'label'     => $item['label'],
				'hardened'  => $this->is_directory_hardened( $dir ),
				'writable'  => is_dir( $dir ) && is_writable( $dir ), // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable
				'exists'    => is_dir( $dir ),
			);
		}
		return $result;
	}

	/**
	 * Detect Nginx by checking the server software header.
	 *
	 * @return bool
	 */
	private function is_nginx() {
		$srv = isset( $_SERVER['SERVER_SOFTWARE'] ) ? strtolower( (string) $_SERVER['SERVER_SOFTWARE'] ) : '';
		return false !== strpos( $srv, 'nginx' );
	}

	/**
	 * Detect IIS by checking the server software header.
	 *
	 * @return bool
	 */
	private function is_iis() {
		$srv = isset( $_SERVER['SERVER_SOFTWARE'] ) ? strtolower( (string) $_SERVER['SERVER_SOFTWARE'] ) : '';
		return false !== strpos( $srv, 'microsoft-iis' );
	}
}

