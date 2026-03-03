<?php
/**
 * User Hardening — User-account and authentication security controls.
 *
 * Provides option-based toggles for:
 *   - User enumeration blocking via .htaccess
 *   - Strong-password enforcement
 *   - Login-attempt rate limiting (transient-based)
 *   - Application Passwords disabling
 *   - WordPress version hiding
 *
 * Each feature stores its enabled state in a WP option named
 * sentinel_hardening_{check_id} so it survives across requests and can be
 * toggled at any time without touching wp-config.php or theme code.
 *
 * @package WP_Sentinel_Security
 * @since   2.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class User_Hardening
 */
class User_Hardening {

	/**
	 * Maximum failed login attempts before an IP is locked out.
	 *
	 * @var int
	 */
	const MAX_LOGIN_ATTEMPTS = 5;   // Default — overridden by sentinel_settings at runtime.
	const LOCKOUT_DURATION   = 900; // Default (15 min) — overridden by sentinel_settings at runtime.

	/**
	 * Get max login attempts from settings (falls back to constant).
	 *
	 * @return int
	 */
	private function get_max_attempts() {
		$s = get_option( 'sentinel_settings', array() );
		return max( 1, (int) ( $s['login_max_attempts'] ?? self::MAX_LOGIN_ATTEMPTS ) );
	}

	/**
	 * Get lockout duration in seconds from settings (falls back to constant).
	 *
	 * @return int
	 */
	private function get_lockout_seconds() {
		$s = get_option( 'sentinel_settings', array() );
		$mins = max( 1, (int) ( $s['login_lockout_mins'] ?? ( self::LOCKOUT_DURATION / 60 ) ) );
		return $mins * 60;
	}
	/**
	 * Absolute path to the root .htaccess file.
	 *
	 * @var string
	 */
	private $htaccess_path;

	/**
	 * Marker label used for user-enumeration .htaccess block.
	 *
	 * @var string
	 */
	const ENUM_MARKER = 'Sentinel-No-User-Enumeration';

	/**
	 * Constructor — resolve paths and register runtime hooks when features are enabled.
	 */
	public function __construct() {
		$this->htaccess_path = ABSPATH . '.htaccess';

		// Register hooks for option-based features that need to run at init time.
		add_action( 'init', array( $this, 'register_runtime_hooks' ) );
	}

	/**
	 * Register runtime WordPress hooks for features that are currently enabled.
	 *
	 * Called on the 'init' action so the option values are available.
	 *
	 * @return void
	 */
	public function register_runtime_hooks() {
		if ( get_option( 'sentinel_hardening_enforce_strong_passwords' ) ) {
			add_action( 'user_profile_update_errors', array( $this, 'enforce_password_strength' ), 10, 3 );
			add_action( 'validate_password_reset',    array( $this, 'enforce_password_strength' ), 10, 2 );
		}

		if ( get_option( 'sentinel_hardening_limit_login_attempts' ) ) {
			add_action( 'wp_login_failed',  array( $this, 'record_failed_login' ) );
			add_filter( 'authenticate',     array( $this, 'check_login_lockout' ), 30, 3 );
		}

		if ( get_option( 'sentinel_hardening_disable_application_passwords' ) ) {
			add_filter( 'wp_is_application_passwords_available_for_user', '__return_false', 100 );
			add_filter( 'wp_is_application_passwords_available',          '__return_false', 100 );
		}

		if ( get_option( 'sentinel_hardening_hide_wp_version' ) ) {
			remove_action( 'wp_head',    'wp_generator' );
			add_filter( 'the_generator',   '__return_empty_string', 100 );
			add_filter( 'script_loader_src', array( $this, 'strip_version_from_src' ), 100 );
			add_filter( 'style_loader_src',  array( $this, 'strip_version_from_src' ), 100 );
		}
	}

	// =========================================================================
	// 1. Disable user enumeration (block ?author=N requests)
	// =========================================================================

	/**
	 * Apply: add an .htaccess RewriteRule to block author-scan requests.
	 *
	 * @return array{status: string, message: string}
	 */
	public function disable_user_enumeration() {
		$rules = array(
			'<IfModule mod_rewrite.c>',
			'    RewriteEngine On',
			'    RewriteCond %{QUERY_STRING} ^author=\d',
			'    RewriteRule ^ - [F,L]',
			'</IfModule>',
		);

		if ( $this->write_htaccess_marker( $rules, self::ENUM_MARKER ) ) {
			update_option( 'sentinel_hardening_disable_user_enumeration', true );
			return array(
				'status'  => 'applied',
				'message' => __( 'User enumeration via ?author= has been blocked.', 'wp-sentinel-security' ),
			);
		}

		return array(
			'status'  => 'error',
			'message' => __( 'Could not write to .htaccess. Check file permissions.', 'wp-sentinel-security' ),
		);
	}

	/**
	 * Revert: remove user-enumeration blocking rule from .htaccess.
	 *
	 * @return array{status: string, message: string}
	 */
	public function revert_disable_user_enumeration() {
		if ( $this->remove_htaccess_marker( self::ENUM_MARKER ) ) {
			delete_option( 'sentinel_hardening_disable_user_enumeration' );
			return array(
				'status'  => 'reverted',
				'message' => __( 'User enumeration block has been removed.', 'wp-sentinel-security' ),
			);
		}

		return array(
			'status'  => 'error',
			'message' => __( 'Could not update .htaccess. Check file permissions.', 'wp-sentinel-security' ),
		);
	}

	/**
	 * Status: check whether user enumeration blocking is active.
	 *
	 * @return array{status: string, details: string}
	 */
	public function status_disable_user_enumeration() {
		if ( ! file_exists( $this->htaccess_path ) ) {
			return array(
				'status'  => 'not_applied',
				'details' => __( '.htaccess not found at WordPress root.', 'wp-sentinel-security' ),
			);
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$contents = file_get_contents( $this->htaccess_path );

		if ( false !== strpos( $contents, '# BEGIN ' . self::ENUM_MARKER ) ) {
			return array(
				'status'  => 'applied',
				'details' => __( 'User enumeration is blocked via .htaccess (managed by Sentinel).', 'wp-sentinel-security' ),
			);
		}

		return array(
			'status'  => 'not_applied',
			'details' => __( 'User enumeration is not blocked.', 'wp-sentinel-security' ),
		);
	}

	// =========================================================================
	// 2. Enforce strong passwords
	// =========================================================================

	/**
	 * Apply: enable strong-password enforcement on profile updates and resets.
	 *
	 * @return array{status: string, message: string}
	 */
	public function enforce_strong_passwords() {
		update_option( 'sentinel_hardening_enforce_strong_passwords', true );
		return array(
			'status'  => 'applied',
			'message' => __( 'Strong-password enforcement has been enabled.', 'wp-sentinel-security' ),
		);
	}

	/**
	 * Revert: disable strong-password enforcement.
	 *
	 * @return array{status: string, message: string}
	 */
	public function revert_enforce_strong_passwords() {
		delete_option( 'sentinel_hardening_enforce_strong_passwords' );
		return array(
			'status'  => 'reverted',
			'message' => __( 'Strong-password enforcement has been disabled.', 'wp-sentinel-security' ),
		);
	}

	/**
	 * Status: check whether strong-password enforcement is active.
	 *
	 * @return array{status: string, details: string}
	 */
	public function status_enforce_strong_passwords() {
		if ( get_option( 'sentinel_hardening_enforce_strong_passwords' ) ) {
			return array(
				'status'  => 'applied',
				'details' => __( 'Strong-password enforcement is active.', 'wp-sentinel-security' ),
			);
		}
		return array(
			'status'  => 'not_applied',
			'details' => __( 'Strong-password enforcement is not enabled.', 'wp-sentinel-security' ),
		);
	}

	/**
	 * Callback: validate password strength during profile updates / resets.
	 *
	 * Requires a minimum length of 12 characters and a mix of character classes.
	 * Hooked to 'user_profile_update_errors' and 'validate_password_reset'.
	 *
	 * @param \WP_Error $errors WP_Error object to append errors to.
	 * @param mixed     $arg2   Second callback arg (varies per hook — ignored here).
	 * @param mixed     $arg3   Third callback arg (varies per hook — ignored here).
	 * @return void
	 */
	public function enforce_password_strength( $errors, $arg2 = null, $arg3 = null ) {
		// Retrieve the password from the correct request variable.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$password = isset( $_POST['pass1'] ) ? wp_unslash( $_POST['pass1'] ) : '';

		if ( empty( $password ) ) {
			return;
		}

		$ok = true;

		if ( strlen( $password ) < 12 ) {
			$ok = false;
		} elseif ( ! preg_match( '/[A-Z]/', $password ) ) {
			$ok = false;
		} elseif ( ! preg_match( '/[a-z]/', $password ) ) {
			$ok = false;
		} elseif ( ! preg_match( '/[0-9]/', $password ) ) {
			$ok = false;
		} elseif ( ! preg_match( '/[^A-Za-z0-9]/', $password ) ) {
			$ok = false;
		}

		if ( ! $ok ) {
			$errors->add(
				'sentinel_weak_password',
				__(
					'Your password must be at least 12 characters long and include uppercase letters, lowercase letters, numbers, and special characters.',
					'wp-sentinel-security'
				)
			);
		}
	}

	// =========================================================================
	// 3. Limit login attempts
	// =========================================================================

	/**
	 * Apply: enable transient-based login-attempt rate limiting.
	 *
	 * @return array{status: string, message: string}
	 */
	public function limit_login_attempts() {
		update_option( 'sentinel_hardening_limit_login_attempts', true );
		return array(
			'status'  => 'applied',
			'message' => __( 'Login-attempt rate limiting has been enabled.', 'wp-sentinel-security' ),
		);
	}

	/**
	 * Revert: disable login-attempt rate limiting.
	 *
	 * @return array{status: string, message: string}
	 */
	public function revert_limit_login_attempts() {
		delete_option( 'sentinel_hardening_limit_login_attempts' );
		return array(
			'status'  => 'reverted',
			'message' => __( 'Login-attempt rate limiting has been disabled.', 'wp-sentinel-security' ),
		);
	}

	/**
	 * Status: check whether login-attempt limiting is active.
	 *
	 * @return array{status: string, details: string}
	 */
	public function status_limit_login_attempts() {
		if ( get_option( 'sentinel_hardening_limit_login_attempts' ) ) {
			return array(
				'status'  => 'applied',
				/* translators: 1: max attempts, 2: lockout minutes */
				'details' => sprintf(
					__( 'Login rate limiting is active: %1$d attempts allowed before a %2$d-minute lockout.', 'wp-sentinel-security' ),
					$this->get_max_attempts(),
					(int) round( $this->get_lockout_seconds() / 60 )
				),
			);
		}
		return array(
			'status'  => 'not_applied',
			'details' => __( 'Login-attempt rate limiting is not enabled.', 'wp-sentinel-security' ),
		);
	}

	/**
	 * Callback: increment the failed-login counter for the requesting IP.
	 *
	 * Hooked to 'wp_login_failed'.
	 *
	 * @param string $username The attempted username (unused but required by hook signature).
	 * @return void
	 */
	public function record_failed_login( $username ) {
		$ip  = $this->get_client_ip();
		$key = 'sentinel_login_fail_' . md5( $ip );

		$attempts = (int) get_transient( $key );
		$attempts++;

		$lockout_secs = $this->get_lockout_seconds();
		set_transient( $key, $attempts, $lockout_secs );

		if ( $attempts >= $this->get_max_attempts() ) {
			set_transient( 'sentinel_login_locked_' . md5( $ip ), 1, $lockout_secs );
		}
	}

	/**
	 * Callback: reject authentication for locked-out IPs.
	 *
	 * Hooked to 'authenticate' with priority 30 (after WP's own auth checks).
	 *
	 * @param \WP_User|\WP_Error|null $user     Current user object or error.
	 * @param string                  $username Submitted username.
	 * @param string                  $password Submitted password.
	 * @return \WP_User|\WP_Error|null Original $user or a WP_Error if locked out.
	 */
	public function check_login_lockout( $user, $username, $password ) {
		$ip  = $this->get_client_ip();
		$key = 'sentinel_login_locked_' . md5( $ip );

		if ( get_transient( $key ) ) {
			return new WP_Error(
				'sentinel_login_locked',
				sprintf(
					/* translators: %d: lockout duration in minutes */
					__( 'Too many failed login attempts. Please try again in %d minutes.', 'wp-sentinel-security' ),
					(int) ceil( $this->get_lockout_seconds() / 60 )
				)
			);
		}

		return $user;
	}

	// =========================================================================
	// 4. Disable Application Passwords
	// =========================================================================

	/**
	 * Apply: disable Application Passwords feature site-wide.
	 *
	 * @return array{status: string, message: string}
	 */
	public function disable_application_passwords() {
		update_option( 'sentinel_hardening_disable_application_passwords', true );
		return array(
			'status'  => 'applied',
			'message' => __( 'Application Passwords have been disabled.', 'wp-sentinel-security' ),
		);
	}

	/**
	 * Revert: re-enable Application Passwords.
	 *
	 * @return array{status: string, message: string}
	 */
	public function revert_disable_application_passwords() {
		delete_option( 'sentinel_hardening_disable_application_passwords' );
		return array(
			'status'  => 'reverted',
			'message' => __( 'Application Passwords have been re-enabled.', 'wp-sentinel-security' ),
		);
	}

	/**
	 * Status: check whether Application Passwords are disabled.
	 *
	 * @return array{status: string, details: string}
	 */
	public function status_disable_application_passwords() {
		if ( get_option( 'sentinel_hardening_disable_application_passwords' ) ) {
			return array(
				'status'  => 'applied',
				'details' => __( 'Application Passwords are disabled site-wide.', 'wp-sentinel-security' ),
			);
		}
		return array(
			'status'  => 'not_applied',
			'details' => __( 'Application Passwords are enabled (WordPress default).', 'wp-sentinel-security' ),
		);
	}

	// =========================================================================
	// 5. Hide WordPress version
	// =========================================================================

	/**
	 * Apply: hide the WordPress version from HTML meta tags, RSS feeds, and scripts.
	 *
	 * @return array{status: string, message: string}
	 */
	public function hide_wp_version() {
		update_option( 'sentinel_hardening_hide_wp_version', true );
		return array(
			'status'  => 'applied',
			'message' => __( 'WordPress version is now hidden from public output.', 'wp-sentinel-security' ),
		);
	}

	/**
	 * Revert: restore WordPress version visibility.
	 *
	 * @return array{status: string, message: string}
	 */
	public function revert_hide_wp_version() {
		delete_option( 'sentinel_hardening_hide_wp_version' );
		return array(
			'status'  => 'reverted',
			'message' => __( 'WordPress version visibility has been restored.', 'wp-sentinel-security' ),
		);
	}

	/**
	 * Status: check whether the WordPress version is hidden.
	 *
	 * @return array{status: string, details: string}
	 */
	public function status_hide_wp_version() {
		if ( get_option( 'sentinel_hardening_hide_wp_version' ) ) {
			return array(
				'status'  => 'applied',
				'details' => __( 'WordPress version is hidden from public output.', 'wp-sentinel-security' ),
			);
		}
		return array(
			'status'  => 'not_applied',
			'details' => __( 'WordPress version is publicly visible.', 'wp-sentinel-security' ),
		);
	}

	/**
	 * Strip ?ver=X.X query parameters from enqueued script and style source URLs.
	 *
	 * Hooked to 'script_loader_src' and 'style_loader_src' when version hiding is active.
	 *
	 * @param string $src URL of the enqueued script or style.
	 * @return string URL without the ver query parameter.
	 */
	public function strip_version_from_src( $src ) {
		if ( is_string( $src ) && false !== strpos( $src, 'ver=' ) ) {
			$src = remove_query_arg( 'ver', $src );
		}
		return $src;
	}

	// =========================================================================
	// Private helpers
	// =========================================================================

	/**
	 * Write a block of .htaccess rules wrapped in Sentinel marker comments.
	 *
	 * @param string[] $rules  Array of rule lines.
	 * @param string   $marker Unique marker label for the block.
	 * @return bool True on success, false on write failure.
	 */
	private function write_htaccess_marker( array $rules, $marker ) {
		$existing = '';
		if ( file_exists( $this->htaccess_path ) ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
			$existing = file_get_contents( $this->htaccess_path );
			if ( false === $existing ) {
				return false;
			}
		}

		// Remove any existing block for this marker.
		$pattern  = '/# BEGIN ' . preg_quote( $marker, '/' ) . '.*?# END ' . preg_quote( $marker, '/' ) . '\n?/s';
		$existing = preg_replace( $pattern, '', $existing );
		$existing = ltrim( $existing );

		$block  = '# BEGIN ' . $marker . "\n";
		$block .= implode( "\n", $rules ) . "\n";
		$block .= '# END ' . $marker . "\n\n";

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		return false !== file_put_contents( $this->htaccess_path, $block . $existing );
	}

	/**
	 * Remove a Sentinel marker block from the root .htaccess file.
	 *
	 * @param string $marker Marker label to remove.
	 * @return bool True on success (or if already absent), false on write failure.
	 */
	private function remove_htaccess_marker( $marker ) {
		if ( ! file_exists( $this->htaccess_path ) ) {
			return true;
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$contents = file_get_contents( $this->htaccess_path );
		if ( false === $contents ) {
			return false;
		}

		$pattern      = '/# BEGIN ' . preg_quote( $marker, '/' ) . '.*?# END ' . preg_quote( $marker, '/' ) . '\n?/s';
		$new_contents = preg_replace( $pattern, '', $contents );

		if ( $new_contents === $contents ) {
			return true; // Nothing to remove.
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		return false !== file_put_contents( $this->htaccess_path, $new_contents );
	}

	/**
	 * Get the best-guess client IP address.
	 *
	 * Prefers REMOTE_ADDR (most reliable) and falls back through proxy headers.
	 *
	 * @return string IP address string.
	 */
	private function get_client_ip() {
		// REMOTE_ADDR is the only header that cannot be spoofed at the network level.
		if ( ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
			return sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
		}

		$headers = array(
			'HTTP_X_FORWARDED_FOR',
			'HTTP_CLIENT_IP',
			'HTTP_X_REAL_IP',
		);

		foreach ( $headers as $header ) {
			if ( ! empty( $_SERVER[ $header ] ) ) {
				$ip = sanitize_text_field( wp_unslash( $_SERVER[ $header ] ) );
				// X-Forwarded-For can be a comma-separated list; take the first.
				$ip = trim( explode( ',', $ip )[0] );
				if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
					return $ip;
				}
			}
		}

		return '0.0.0.0';
	}
}
