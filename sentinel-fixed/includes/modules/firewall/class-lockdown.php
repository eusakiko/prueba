<?php
/**
 * Site Lockdown Mode.
 *
 * One-click emergency lockdown that:
 * - Blocks all login attempts except from the current admin's IP
 * - Disables XML-RPC
 * - Disables REST API for unauthenticated users
 * - Triggers an immediate full scan
 * - Sends alerts on all configured channels
 * - Auto-disables after a configurable timeout (default 24 hours)
 *
 * @package WP_Sentinel_Security
 * @since   2.2.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Sentinel_Lockdown
 */
class Sentinel_Lockdown {

	/**
	 * Option key for lockdown state.
	 *
	 * @var string
	 */
	const OPTION_KEY = 'sentinel_lockdown';

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
	 * Initialize — register hooks when lockdown is active.
	 *
	 * @return void
	 */
	public function init() {
		// Auto-disable cron hook.
		add_action( 'sentinel_lockdown_auto_disable', array( $this, 'deactivate' ) );

		if ( ! $this->is_active() ) {
			return;
		}

		// Block XML-RPC.
		add_filter( 'xmlrpc_enabled', '__return_false' );

		// Block REST API for unauthenticated users.
		add_filter( 'rest_authentication_errors', array( $this, 'block_unauthenticated_rest' ) );

		// Block login attempts from non-admin IPs.
		add_action( 'login_init', array( $this, 'enforce_ip_restriction' ) );

		// Admin banner notice.
		add_action( 'admin_notices', array( $this, 'render_admin_banner' ) );
	}

	/**
	 * Activate lockdown mode.
	 *
	 * @param int    $duration_hours How long to lock down (default 24 hours).
	 * @param string $admin_ip       IP to whitelist for login (defaults to current IP).
	 * @return bool True on success.
	 */
	public function activate( $duration_hours = 24, $admin_ip = '' ) {
		if ( empty( $admin_ip ) && class_exists( 'Sentinel_Helper' ) ) {
			$admin_ip = Sentinel_Helper::get_client_ip();
		}

		$lockdown = array(
			'active'       => true,
			'activated_at' => time(),
			'expires_at'   => time() + ( (int) $duration_hours * HOUR_IN_SECONDS ),
			'admin_ip'     => sanitize_text_field( $admin_ip ),
			'activated_by' => get_current_user_id(),
		);

		update_option( self::OPTION_KEY, $lockdown );

		// Schedule auto-disable.
		wp_clear_scheduled_hook( 'sentinel_lockdown_auto_disable' );
		wp_schedule_single_event( $lockdown['expires_at'], 'sentinel_lockdown_auto_disable' );

		// Log the event.
		do_action( 'sentinel_activity_log', 'lockdown_activated', 'firewall', 'critical',
			sprintf( 'Site lockdown activated by user %d from IP %s. Expires in %d hours.', get_current_user_id(), $admin_ip, $duration_hours )
		);

		// Send alerts.
		do_action( 'sentinel_send_alert',
			__( '🔒 Site Lockdown Activated', 'wp-sentinel-security' ),
			sprintf(
				__( 'WP Sentinel has activated site lockdown mode. Only the admin IP (%s) can log in. Lockdown expires in %d hours.', 'wp-sentinel-security' ),
				$admin_ip,
				$duration_hours
			),
			array( 'severity' => 'critical', 'event_type' => 'lockdown_activated' )
		);

		// Trigger immediate full scan.
		do_action( 'sentinel_trigger_scan', 'full', 'lockdown' );

		return true;
	}

	/**
	 * Deactivate lockdown mode.
	 *
	 * @return void
	 */
	public function deactivate() {
		delete_option( self::OPTION_KEY );
		wp_clear_scheduled_hook( 'sentinel_lockdown_auto_disable' );

		do_action( 'sentinel_activity_log', 'lockdown_deactivated', 'firewall', 'info',
			'Site lockdown mode has been deactivated.'
		);
	}

	/**
	 * Check whether lockdown mode is currently active.
	 *
	 * @return bool
	 */
	public function is_active() {
		$lockdown = get_option( self::OPTION_KEY, array() );

		if ( empty( $lockdown['active'] ) ) {
			return false;
		}

		// Auto-expire if past expires_at.
		if ( ! empty( $lockdown['expires_at'] ) && time() > (int) $lockdown['expires_at'] ) {
			$this->deactivate();
			return false;
		}

		return true;
	}

	/**
	 * Get current lockdown state data.
	 *
	 * @return array|null Lockdown data or null if not active.
	 */
	public function get_state() {
		if ( ! $this->is_active() ) {
			return null;
		}
		return get_option( self::OPTION_KEY, array() );
	}

	/**
	 * Block REST API access for unauthenticated users during lockdown.
	 *
	 * Hooked to 'rest_authentication_errors'.
	 *
	 * @param mixed $errors Existing authentication errors.
	 * @return WP_Error|mixed
	 */
	public function block_unauthenticated_rest( $errors ) {
		if ( ! is_user_logged_in() ) {
			return new WP_Error(
				'rest_lockdown',
				__( 'The REST API is disabled during site lockdown.', 'wp-sentinel-security' ),
				array( 'status' => 403 )
			);
		}
		return $errors;
	}

	/**
	 * Enforce IP restriction on the login page during lockdown.
	 *
	 * Hooked to 'login_init'.
	 *
	 * @return void
	 */
	public function enforce_ip_restriction() {
		$lockdown = get_option( self::OPTION_KEY, array() );
		$admin_ip = $lockdown['admin_ip'] ?? '';

		if ( empty( $admin_ip ) ) {
			return;
		}

		$client_ip = class_exists( 'Sentinel_Helper' )
			? Sentinel_Helper::get_client_ip()
			: ( ! empty( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '' );

		if ( $client_ip !== $admin_ip ) {
			wp_die(
				esc_html__( 'Login is restricted during site lockdown mode.', 'wp-sentinel-security' ),
				esc_html__( 'Lockdown Active', 'wp-sentinel-security' ),
				array( 'response' => 403 )
			);
		}
	}

	/**
	 * Render admin banner notice when lockdown is active.
	 *
	 * @return void
	 */
	public function render_admin_banner() {
		$state = $this->get_state();
		if ( ! $state ) {
			return;
		}

		$expires_in = max( 0, (int) $state['expires_at'] - time() );
		$hours      = (int) floor( $expires_in / HOUR_IN_SECONDS );
		$minutes    = (int) floor( ( $expires_in % HOUR_IN_SECONDS ) / MINUTE_IN_SECONDS );

		printf(
			'<div class="notice notice-error sentinel-lockdown-notice"><p><strong>%s</strong> %s &mdash; %s</p></div>',
			esc_html__( '🔒 WP Sentinel: Site Lockdown Active', 'wp-sentinel-security' ),
			esc_html(
				sprintf(
					__( 'Login is restricted to IP %s.', 'wp-sentinel-security' ),
					$state['admin_ip']
				)
			),
			esc_html(
				sprintf(
					__( 'Auto-disables in %dh %dm.', 'wp-sentinel-security' ),
					$hours,
					$minutes
				)
			)
		);
	}
}
