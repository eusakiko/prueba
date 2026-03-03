<?php
/**
 * WP-Config Hardening — Manages security-related wp-config.php constants.
 *
 * Each constant is injected before the "That's all, stop editing!" marker
 * and identified by an inline comment so it can be safely reverted later.
 * A backup of wp-config.php is created before any modification.
 *
 * @package WP_Sentinel_Security
 * @since   2.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WP_Config_Hardening
 *
 * Provides apply / revert / status triplets for each wp-config.php constant
 * that Sentinel can manage.  Status values: 'applied' | 'not_applied' | 'partial'.
 */
class WP_Config_Hardening {

	/**
	 * Absolute path to wp-config.php.
	 *
	 * @var string
	 */
	private $wp_config_path;

	/**
	 * Inline comment appended to every Sentinel-added line so it can be
	 * identified and removed without touching user-managed constants.
	 *
	 * @var string
	 */
	const SENTINEL_COMMENT = '// Added by WP Sentinel Security';

	/**
	 * The stop-editing marker used to anchor new constant insertions.
	 *
	 * @var string
	 */
	const STOP_EDITING_MARKER = "/* That's all, stop editing!";

	/**
	 * Constructor — resolves the wp-config.php path.
	 */
	public function __construct() {
		$this->wp_config_path = ABSPATH . 'wp-config.php';
	}

	// =========================================================================
	// 1. FORCE_SSL_ADMIN
	// =========================================================================

	/**
	 * Apply: define FORCE_SSL_ADMIN to enforce HTTPS on the admin area.
	 *
	 * @return array{status: string, message: string}
	 */
	public function force_ssl_admin() {
		return $this->apply_constant( 'FORCE_SSL_ADMIN', 'true' );
	}

	/**
	 * Revert: remove Sentinel-managed FORCE_SSL_ADMIN definition.
	 *
	 * @return array{status: string, message: string}
	 */
	public function revert_force_ssl_admin() {
		return $this->revert_constant( 'FORCE_SSL_ADMIN' );
	}

	/**
	 * Status: check whether FORCE_SSL_ADMIN is active.
	 *
	 * @return array{status: string, details: string}
	 */
	public function status_force_ssl_admin() {
		return $this->status_constant( 'FORCE_SSL_ADMIN', defined( 'FORCE_SSL_ADMIN' ) && FORCE_SSL_ADMIN );
	}

	// =========================================================================
	// 2. WP_DEBUG (enforce false)
	// =========================================================================

	/**
	 * Apply: set WP_DEBUG to false to suppress error output in production.
	 *
	 * @return array{status: string, message: string}
	 */
	public function disable_debug() {
		// If WP_DEBUG is already false by a user-managed line we still add our
		// enforcement line so we can track and revert it.
		return $this->apply_constant( 'WP_DEBUG', 'false' );
	}

	/**
	 * Revert: remove Sentinel-managed WP_DEBUG definition.
	 *
	 * @return array{status: string, message: string}
	 */
	public function revert_disable_debug() {
		return $this->revert_constant( 'WP_DEBUG' );
	}

	/**
	 * Status: check whether WP_DEBUG is currently false.
	 *
	 * @return array{status: string, details: string}
	 */
	public function status_disable_debug() {
		$debug_off = defined( 'WP_DEBUG' ) && ! WP_DEBUG;
		return $this->status_constant( 'WP_DEBUG', $debug_off );
	}

	// =========================================================================
	// 3. WP_POST_REVISIONS
	// =========================================================================

	/**
	 * Apply: limit post revisions to 5 to reduce database bloat.
	 *
	 * @return array{status: string, message: string}
	 */
	public function limit_post_revisions() {
		return $this->apply_constant( 'WP_POST_REVISIONS', '5' );
	}

	/**
	 * Revert: remove Sentinel-managed WP_POST_REVISIONS definition.
	 *
	 * @return array{status: string, message: string}
	 */
	public function revert_limit_post_revisions() {
		return $this->revert_constant( 'WP_POST_REVISIONS' );
	}

	/**
	 * Status: check current post-revision limit.
	 *
	 * @return array{status: string, details: string}
	 */
	public function status_limit_post_revisions() {
		$limited = defined( 'WP_POST_REVISIONS' ) && is_int( WP_POST_REVISIONS ) && WP_POST_REVISIONS <= 5;
		return $this->status_constant( 'WP_POST_REVISIONS', $limited );
	}

	// =========================================================================
	// 4. AUTOSAVE_INTERVAL
	// =========================================================================

	/**
	 * Apply: set auto-save interval to 300 seconds (5 minutes) to reduce write load.
	 *
	 * @return array{status: string, message: string}
	 */
	public function set_autosave_interval() {
		return $this->apply_constant( 'AUTOSAVE_INTERVAL', '300' );
	}

	/**
	 * Revert: remove Sentinel-managed AUTOSAVE_INTERVAL definition.
	 *
	 * @return array{status: string, message: string}
	 */
	public function revert_set_autosave_interval() {
		return $this->revert_constant( 'AUTOSAVE_INTERVAL' );
	}

	/**
	 * Status: check current auto-save interval.
	 *
	 * @return array{status: string, details: string}
	 */
	public function status_set_autosave_interval() {
		$set = defined( 'AUTOSAVE_INTERVAL' ) && AUTOSAVE_INTERVAL >= 300;
		return $this->status_constant( 'AUTOSAVE_INTERVAL', $set );
	}

	// =========================================================================
	// 5. DISALLOW_FILE_EDIT
	// =========================================================================

	/**
	 * Apply: define DISALLOW_FILE_EDIT to disable the theme/plugin file editor.
	 *
	 * @return array{status: string, message: string}
	 */
	public function disable_file_editor() {
		return $this->apply_constant( 'DISALLOW_FILE_EDIT', 'true' );
	}

	/**
	 * Revert: remove Sentinel-managed DISALLOW_FILE_EDIT definition.
	 *
	 * @return array{status: string, message: string}
	 */
	public function revert_disable_file_editor() {
		return $this->revert_constant( 'DISALLOW_FILE_EDIT' );
	}

	/**
	 * Status: check whether the file editor is disabled.
	 *
	 * @return array{status: string, details: string}
	 */
	public function status_disable_file_editor() {
		return $this->status_constant( 'DISALLOW_FILE_EDIT', defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT );
	}

	// =========================================================================
	// 6. DISALLOW_UNFILTERED_HTML
	// =========================================================================

	/**
	 * Apply: define DISALLOW_UNFILTERED_HTML to prevent raw HTML from non-admins.
	 *
	 * @return array{status: string, message: string}
	 */
	public function disable_unfiltered_html() {
		return $this->apply_constant( 'DISALLOW_UNFILTERED_HTML', 'true' );
	}

	/**
	 * Revert: remove Sentinel-managed DISALLOW_UNFILTERED_HTML definition.
	 *
	 * @return array{status: string, message: string}
	 */
	public function revert_disable_unfiltered_html() {
		return $this->revert_constant( 'DISALLOW_UNFILTERED_HTML' );
	}

	/**
	 * Status: check whether unfiltered HTML is disallowed.
	 *
	 * @return array{status: string, details: string}
	 */
	public function status_disable_unfiltered_html() {
		return $this->status_constant(
			'DISALLOW_UNFILTERED_HTML',
			defined( 'DISALLOW_UNFILTERED_HTML' ) && DISALLOW_UNFILTERED_HTML
		);
	}

	// =========================================================================
	// 7. EMPTY_TRASH_DAYS
	// =========================================================================

	/**
	 * Apply: set EMPTY_TRASH_DAYS to 7 to reduce attack surface from trashed items.
	 *
	 * @return array{status: string, message: string}
	 */
	public function set_empty_trash_days() {
		return $this->apply_constant( 'EMPTY_TRASH_DAYS', '7' );
	}

	/**
	 * Revert: remove Sentinel-managed EMPTY_TRASH_DAYS definition.
	 *
	 * @return array{status: string, message: string}
	 */
	public function revert_set_empty_trash_days() {
		return $this->revert_constant( 'EMPTY_TRASH_DAYS' );
	}

	/**
	 * Status: check current trash-emptying schedule.
	 *
	 * @return array{status: string, details: string}
	 */
	public function status_set_empty_trash_days() {
		$set = defined( 'EMPTY_TRASH_DAYS' ) && EMPTY_TRASH_DAYS <= 7;
		return $this->status_constant( 'EMPTY_TRASH_DAYS', $set );
	}

	// =========================================================================
	// Private helpers
	// =========================================================================

	/**
	 * Apply a constant to wp-config.php.
	 *
	 * Creates a backup, then injects the define() call before the stop-editing
	 * marker. Does nothing if the exact Sentinel-managed line is already present.
	 *
	 * @param string $constant PHP constant name.
	 * @param string $value    Raw PHP value string (e.g. 'true', '5', "'value'").
	 * @return array{status: string, message: string}
	 */
	private function apply_constant( $constant, $value ) {
		if ( ! $this->config_is_writable() ) {
			return array(
				'status'  => 'error',
				'message' => __( 'wp-config.php is not writable. Check file permissions.', 'wp-sentinel-security' ),
			);
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$contents = file_get_contents( $this->wp_config_path );
		if ( false === $contents ) {
			return array(
				'status'  => 'error',
				'message' => __( 'Could not read wp-config.php.', 'wp-sentinel-security' ),
			);
		}

		// Already managed by Sentinel — idempotent.
		if ( $this->has_sentinel_constant( $contents, $constant ) ) {
			return array(
				'status'  => 'already_applied',
				/* translators: %s: constant name */
				'message' => sprintf( __( '%s is already managed by Sentinel.', 'wp-sentinel-security' ), $constant ),
			);
		}

		$this->backup_config( $contents );

		$new_line     = "define( '" . $constant . "', " . $value . ' ); ' . self::SENTINEL_COMMENT . "\n";
		$new_contents = $this->inject_before_stop_marker( $contents, $new_line );

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		if ( false === file_put_contents( $this->wp_config_path, $new_contents ) ) {
			return array(
				'status'  => 'error',
				'message' => __( 'Could not write to wp-config.php.', 'wp-sentinel-security' ),
			);
		}

		return array(
			'status'  => 'applied',
			/* translators: %s: constant name */
			'message' => sprintf( __( '%s has been configured in wp-config.php.', 'wp-sentinel-security' ), $constant ),
		);
	}

	/**
	 * Revert a Sentinel-managed constant from wp-config.php.
	 *
	 * Only removes lines that carry the SENTINEL_COMMENT marker.
	 *
	 * @param string $constant PHP constant name.
	 * @return array{status: string, message: string}
	 */
	private function revert_constant( $constant ) {
		if ( ! $this->config_is_writable() ) {
			return array(
				'status'  => 'error',
				'message' => __( 'wp-config.php is not writable. Check file permissions.', 'wp-sentinel-security' ),
			);
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$contents = file_get_contents( $this->wp_config_path );
		if ( false === $contents ) {
			return array(
				'status'  => 'error',
				'message' => __( 'Could not read wp-config.php.', 'wp-sentinel-security' ),
			);
		}

		$pattern      = '/^[^\S\r\n]*define\s*\(\s*[\'"]' . preg_quote( $constant, '/' ) . '[\'"].*' . preg_quote( self::SENTINEL_COMMENT, '/' ) . '.*\n?/m';
		$new_contents = preg_replace( $pattern, '', $contents );

		if ( $new_contents === $contents ) {
			return array(
				'status'  => 'not_found',
				/* translators: %s: constant name */
				'message' => sprintf( __( 'No Sentinel-managed %s definition found to remove.', 'wp-sentinel-security' ), $constant ),
			);
		}

		$this->backup_config( $contents );

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		if ( false === file_put_contents( $this->wp_config_path, $new_contents ) ) {
			return array(
				'status'  => 'error',
				'message' => __( 'Could not write to wp-config.php.', 'wp-sentinel-security' ),
			);
		}

		return array(
			'status'  => 'reverted',
			/* translators: %s: constant name */
			'message' => sprintf( __( '%s definition has been removed from wp-config.php.', 'wp-sentinel-security' ), $constant ),
		);
	}

	/**
	 * Return status information for a given constant.
	 *
	 * @param string $constant        PHP constant name.
	 * @param bool   $runtime_active  Whether the constant is effectively active at runtime.
	 * @return array{status: string, details: string}
	 */
	private function status_constant( $constant, $runtime_active ) {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$contents = file_exists( $this->wp_config_path ) ? file_get_contents( $this->wp_config_path ) : '';

		$sentinel_managed = $this->has_sentinel_constant( $contents, $constant );

		if ( $sentinel_managed && $runtime_active ) {
			return array(
				'status'  => 'applied',
				/* translators: %s: constant name */
				'details' => sprintf( __( '%s is defined and managed by Sentinel.', 'wp-sentinel-security' ), $constant ),
			);
		}

		if ( $runtime_active ) {
			return array(
				'status'  => 'partial',
				/* translators: %s: constant name */
				'details' => sprintf( __( '%s is active at runtime but not managed by Sentinel.', 'wp-sentinel-security' ), $constant ),
			);
		}

		return array(
			'status'  => 'not_applied',
			/* translators: %s: constant name */
			'details' => sprintf( __( '%s is not configured or not active.', 'wp-sentinel-security' ), $constant ),
		);
	}

	/**
	 * Check whether the given constant has a Sentinel-managed definition.
	 *
	 * @param string $contents  Full text of wp-config.php.
	 * @param string $constant  Constant name to search for.
	 * @return bool
	 */
	private function has_sentinel_constant( $contents, $constant ) {
		$pattern = '/define\s*\(\s*[\'"]' . preg_quote( $constant, '/' ) . '[\'"].*' . preg_quote( self::SENTINEL_COMMENT, '/' ) . '/';
		return (bool) preg_match( $pattern, $contents );
	}

	/**
	 * Inject a line of PHP before the stop-editing marker in wp-config.php content.
	 *
	 * Falls back to appending at end-of-file if the marker is absent.
	 *
	 * @param string $contents Full text of wp-config.php.
	 * @param string $new_line The line to inject (including trailing newline).
	 * @return string Modified content.
	 */
	private function inject_before_stop_marker( $contents, $new_line ) {
		if ( false !== strpos( $contents, self::STOP_EDITING_MARKER ) ) {
			return str_replace( self::STOP_EDITING_MARKER, $new_line . self::STOP_EDITING_MARKER, $contents );
		}
		// No marker found — append before the closing PHP tag if present.
		if ( false !== strpos( $contents, '?>' ) ) {
			return str_replace( '?>', $new_line . '?>', $contents );
		}
		return $contents . "\n" . $new_line;
	}

	/**
	 * Write a backup of the current wp-config.php next to the original.
	 *
	 * The backup is written with restrictive permissions (0400) to prevent
	 * other system users from reading the sensitive configuration. The backup
	 * is overwritten on each modification so it always holds the state
	 * immediately prior to the last Sentinel change.
	 *
	 * @param string $contents Current file contents.
	 * @return bool True on success, false if the backup could not be written.
	 */
	private function backup_config( $contents ) {
		$backup_path = $this->wp_config_path . '.sentinel-bak';
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		$written = file_put_contents( $backup_path, $contents );
		if ( false !== $written && file_exists( $backup_path ) ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod
			chmod( $backup_path, 0400 );
		}
		return false !== $written;
	}

	/**
	 * Check whether wp-config.php exists and is writable.
	 *
	 * @return bool
	 */
	private function config_is_writable() {
		return file_exists( $this->wp_config_path ) && is_writable( $this->wp_config_path );
	}
}
