<?php
/**
 * Alert engine.
 *
 * Orchestrates alert triggering, channel dispatch, throttling,
 * and AJAX handlers for the admin alerts interface.
 *
 * @package WP_Sentinel_Security
 * @since   2.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Alert_Engine
 */
class Alert_Engine {

	/**
	 * Plugin settings.
	 *
	 * @var array
	 */
	private $settings;

	/**
	 * Loaded channel instances.
	 *
	 * @var array
	 */
	private $channels = array();

	/**
	 * Constructor.
	 *
	 * @param array $settings Plugin settings.
	 */
	public function __construct( $settings = array() ) {
		$this->settings = $settings;
	}

	/**
	 * Initialize the engine: load channel classes and register AJAX hooks.
	 *
	 * @return void
	 */
	public function init() {
		$base = SENTINEL_PLUGIN_DIR . 'includes/modules/alerts/';
		require_once $base . 'class-alert-email.php';
		require_once $base . 'class-alert-slack.php';
		require_once $base . 'class-alert-telegram.php';
		require_once $base . 'class-alert-discord.php';
		require_once $base . 'class-alert-webhook.php';

		$this->channels = array(
			'email'    => new Alert_Email( $this->settings ),
			'slack'    => new Alert_Slack( $this->settings ),
			'telegram' => new Alert_Telegram( $this->settings ),
			'discord'  => new Alert_Discord( $this->settings ),
			'webhook'  => new Alert_Webhook( $this->settings ),
		);

		add_action( 'wp_ajax_sentinel_test_alert',    array( $this, 'ajax_test_alert' ) );
		add_action( 'wp_ajax_sentinel_get_alerts',    array( $this, 'ajax_get_alerts' ) );
		add_action( 'wp_ajax_sentinel_dismiss_alert', array( $this, 'ajax_dismiss_alert' ) );

		/**
		 * Bridge the generic sentinel_send_alert action (fired by Blacklist_Monitor,
		 * Lockdown and other modules) to the Alert_Engine::trigger_alert() method.
		 *
		 * Signature: do_action( 'sentinel_send_alert', $subject, $message, $data )
		 * The alert engine's trigger_alert() expects an event_type + data array, so
		 * we derive the event_type from $data['event_type'] when present, falling
		 * back to a generic key derived from the subject.
		 */
		add_action( 'sentinel_send_alert', array( $this, 'handle_send_alert_action' ), 10, 3 );
	}

	/**
	 * Bridge for the sentinel_send_alert do_action hook.
	 *
	 * Modules that call do_action('sentinel_send_alert', $subject, $message, $context)
	 * end up here.  We pass the call through to the existing send() methods on each
	 * enabled channel directly (bypassing the event-type throttle, because these are
	 * already considered urgent / non-throttleable events such as blacklist detection).
	 *
	 * @param string $subject The alert subject / title.
	 * @param string $message The alert body.
	 * @param array  $context Optional context: severity, event_type, etc.
	 * @return void
	 */
	public function handle_send_alert_action( $subject, $message, $context = array() ) {
		// Build a data array compatible with the channel send() signature.
		$severity   = $context['severity']   ?? 'high';
		$event_type = $context['event_type'] ?? 'generic_alert';

		$data = array_merge( $context, array(
			'severity'   => sanitize_text_field( $severity ),
			'event_type' => sanitize_text_field( $event_type ),
		) );

		// Throttle: same event type should not spam every 6 hours (blacklist TTL).
		$transient_key = 'sentinel_direct_alert_' . md5( $event_type );
		if ( get_transient( $transient_key ) ) {
			return;
		}
		set_transient( $transient_key, true, HOUR_IN_SECONDS );

		$enabled_channels = $this->settings['alert_channels'] ?? array( 'email' );
		foreach ( $enabled_channels as $channel ) {
			if ( isset( $this->channels[ $channel ] ) ) {
				$this->channels[ $channel ]->send(
					sanitize_text_field( $subject ),
					wp_kses_post( $message ),
					$data
				);
			}
		}

		// Log to activity log.
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$wpdb->insert(
			"{$wpdb->prefix}sentinel_activity_log",
			array(
				'user_id'        => 0,
				'event_type'     => sanitize_text_field( $event_type ),
				'event_category' => 'alert',
				'severity'       => sanitize_text_field( $severity ),
				'description'    => sanitize_text_field( $subject ),
				'ip_address'     => '',
				'created_at'     => current_time( 'mysql' ),
			),
			array( '%d', '%s', '%s', '%s', '%s', '%s', '%s' )
		);
	}

	/**
	 * Trigger an alert across enabled channels (with throttle).
	 *
	 * @param string $event_type Event identifier.
	 * @param array  $data       Event data: severity, extra context.
	 * @return void
	 */
	public function trigger_alert( $event_type, $data = array() ) {
		$transient_key = 'sentinel_alert_' . md5( $event_type );

		// Skip if throttled.
		if ( get_transient( $transient_key ) ) {
			return;
		}

		// Per-event-type throttle window. Critical events use shorter windows so
		// repeated attacks are not silently suppressed for a full hour.
		$defaults = array(
			'brute_force' => 5 * MINUTE_IN_SECONDS,
			'malware_detected' => 5 * MINUTE_IN_SECONDS,
			'lockdown_activated' => 5 * MINUTE_IN_SECONDS,
			'waf_blocked' => 15 * MINUTE_IN_SECONDS,
			'ip_blocked' => 15 * MINUTE_IN_SECONDS,
			'file_integrity_alert' => 30 * MINUTE_IN_SECONDS,
			'login_failed' => 30 * MINUTE_IN_SECONDS,
		);
		$custom = (array) ( $this->settings['alert_throttle_windows'] ?? array() );
		$window = array_merge( $defaults, $custom )[ $event_type ] ?? HOUR_IN_SECONDS;
		$window = (int) apply_filters( 'sentinel_alert_throttle_window', $window, $event_type );
		set_transient( $transient_key, true, max( 60, $window ) );

		$severity = $this->get_severity_for_event( $event_type );
		$data     = array_merge( $data, array( 'severity' => $data['severity'] ?? $severity ) );

		list( $subject, $message ) = $this->get_message_for_event( $event_type, $data );

		$enabled_channels = $this->settings['alert_channels'] ?? array( 'email' );

		foreach ( $enabled_channels as $channel ) {
			if ( isset( $this->channels[ $channel ] ) ) {
				$this->channels[ $channel ]->send( $subject, $message, $data );
			}
		}

		// Log the alert.
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$wpdb->insert(
			"{$wpdb->prefix}sentinel_activity_log",
			array(
				'user_id'        => get_current_user_id(),
				'event_type'     => sanitize_text_field( $event_type ),
				'event_category' => 'alert',
				'severity'       => sanitize_text_field( $data['severity'] ),
				'description'    => sanitize_text_field( $subject ),
				'ip_address'     => class_exists( 'Sentinel_Helper' ) ? Sentinel_Helper::get_client_ip() : '',
				'user_agent'     => sanitize_text_field( $_SERVER['HTTP_USER_AGENT'] ?? '' ), // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotValidated
				'object_type'    => sanitize_text_field( $data['object_type'] ?? '' ),
				'object_id'      => sanitize_text_field( $data['object_id'] ?? '' ),
				'metadata'       => wp_json_encode( $data ),
				'created_at'     => current_time( 'mysql' ),
			),
			array( '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s' )
		);
	}

	/**
	 * Determine the default severity for a given event type.
	 *
	 * @param string $event_type Event identifier.
	 * @return string Severity level.
	 */
	private function get_severity_for_event( $event_type ) {
		$map = array(
			'critical_vulnerability'   => 'critical',
			'malware_detected'         => 'critical',
			'backup_failed'            => 'high',
			'login_failed_threshold'   => 'high',
			'file_changed'             => 'medium',
			'hardening_changed'        => 'medium',
			'scan_complete'            => 'info',
		);
		return $map[ $event_type ] ?? 'info';
	}

	/**
	 * Build subject and message strings for a given event type.
	 *
	 * @param string $event_type Event identifier.
	 * @param array  $data       Event data for contextual messages.
	 * @return array [ subject, message ]
	 */
	private function get_message_for_event( $event_type, $data ) {
		switch ( $event_type ) {
			case 'critical_vulnerability':
				$subject = __( 'Critical Vulnerability Detected', 'wp-sentinel-security' );
				$message = __( 'A critical vulnerability has been detected on your WordPress site. Immediate action is required.', 'wp-sentinel-security' );
				break;

			case 'scan_complete':
				$subject = __( 'Security Scan Completed', 'wp-sentinel-security' );
				$found   = isset( $data['vulnerabilities_found'] ) ? absint( $data['vulnerabilities_found'] ) : 0;
				$message = sprintf(
					/* translators: %d: Number of vulnerabilities */
					__( 'Security scan completed. %d vulnerabilities found.', 'wp-sentinel-security' ),
					$found
				);
				break;

			case 'file_changed':
				$subject = __( 'File Modification Detected', 'wp-sentinel-security' );
				$file    = sanitize_text_field( $data['file'] ?? __( 'unknown file', 'wp-sentinel-security' ) );
				$message = sprintf(
					/* translators: %s: File path */
					__( 'An unexpected file modification was detected: %s', 'wp-sentinel-security' ),
					$file
				);
				break;

			case 'login_failed_threshold':
				$subject = __( 'Brute Force Attack Alert', 'wp-sentinel-security' );
				$message = __( 'Multiple failed login attempts detected. A brute force attack may be in progress.', 'wp-sentinel-security' );
				break;

			case 'hardening_changed':
				$subject = __( 'Hardening Configuration Changed', 'wp-sentinel-security' );
				$message = __( 'A hardening setting has been modified on your WordPress site.', 'wp-sentinel-security' );
				break;

			case 'backup_failed':
				$subject = __( 'Backup Failed', 'wp-sentinel-security' );
				$message = __( 'An automated backup has failed. Please check your backup configuration.', 'wp-sentinel-security' );
				break;

			case 'malware_detected':
				$subject = __( 'Malware Detected', 'wp-sentinel-security' );
				$message = __( 'Potential malware has been detected on your WordPress site. Immediate action is required.', 'wp-sentinel-security' );
				break;

			default:
				$subject = __( 'WP Sentinel Security Alert', 'wp-sentinel-security' );
				$message = sanitize_text_field( $data['message'] ?? __( 'A security event occurred on your WordPress site.', 'wp-sentinel-security' ) );
				break;
		}

		return array( $subject, $message );
	}

	/**
	 * Get paginated alert history from the activity log.
	 *
	 * @param int $page     Page number (1-based).
	 * @param int $per_page Items per page.
	 * @return array
	 */
	public function get_alert_history( $page = 1, $per_page = 20 ) {
		return Sentinel_DB::get_activity_log( array( 'event_category' => 'alert' ), $page, $per_page );
	}

	// -------------------------------------------------------------------------
	// AJAX handlers
	// -------------------------------------------------------------------------

	/**
	 * AJAX: send a test alert on a specific channel.
	 *
	 * @return void
	 */
	public function ajax_test_alert() {
		check_ajax_referer( 'sentinel_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'wp-sentinel-security' ) ), 403 );
		}

		$channel = isset( $_POST['channel'] ) ? sanitize_text_field( wp_unslash( $_POST['channel'] ) ) : 'email';

		if ( ! isset( $this->channels[ $channel ] ) ) {
			wp_send_json_error( array( 'message' => __( 'Unknown alert channel.', 'wp-sentinel-security' ) ) );
		}

		// Capture any wp_mail errors for a useful diagnostic.
		$mail_error_message = '';
		$mail_error_handler = function( $error ) use ( &$mail_error_message ) {
			if ( isset( $error['message'] ) ) {
				$mail_error_message = $error['message'];
			}
		};
		add_action( 'wp_mail_failed', $mail_error_handler );

		$result = $this->channels[ $channel ]->send(
			__( 'WP Sentinel Security — Test Alert', 'wp-sentinel-security' ),
			__( 'This is a test alert from WP Sentinel Security. Your alert channel is working correctly.', 'wp-sentinel-security' ),
			array( 'severity' => 'info' )
		);

		remove_action( 'wp_mail_failed', $mail_error_handler );

		if ( is_wp_error( $result ) ) {
			wp_send_json_error( array( 'message' => $result->get_error_message() ) );
		}

		if ( false === $result ) {
			// Give a helpful message depending on channel.
			if ( 'email' === $channel ) {
				$hint = $mail_error_message
					? $mail_error_message
					: __( 'WordPress could not send the email. In Docker/local environments you need an SMTP plugin (e.g. WP Mail SMTP) or configure a mail server. The alert email would go to: ', 'wp-sentinel-security' ) . get_option( 'admin_email' );
				wp_send_json_error( array( 'message' => $hint ) );
			}
			wp_send_json_error( array( 'message' => __( 'Alert could not be sent. Check channel credentials in Settings.', 'wp-sentinel-security' ) ) );
		}

		wp_send_json_success( array( 'message' => __( 'Test alert sent successfully.', 'wp-sentinel-security' ) ) );
	}

	/**
	 * AJAX: get paginated alert history.
	 *
	 * @return void
	 */
	public function ajax_get_alerts() {
		check_ajax_referer( 'sentinel_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'wp-sentinel-security' ) ), 403 );
		}

		$page     = isset( $_GET['page'] ) ? absint( $_GET['page'] ) : 1;
		$per_page = isset( $_GET['per_page'] ) ? absint( $_GET['per_page'] ) : 20;

		wp_send_json_success( $this->get_alert_history( $page, $per_page ) );
	}

	/**
	 * AJAX: dismiss (acknowledge) an alert.
	 *
	 * @return void
	 */
	public function ajax_dismiss_alert() {
		check_ajax_referer( 'sentinel_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'wp-sentinel-security' ) ), 403 );
		}

		$alert_id = isset( $_POST['alert_id'] ) ? absint( $_POST['alert_id'] ) : 0;

		if ( ! $alert_id ) {
			wp_send_json_error( array( 'message' => __( 'Invalid alert ID.', 'wp-sentinel-security' ) ) );
		}

		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$updated = $wpdb->update(
			"{$wpdb->prefix}sentinel_activity_log",
			array( 'metadata' => wp_json_encode( array( 'dismissed' => true, 'dismissed_by' => get_current_user_id() ) ) ),
			array( 'id' => $alert_id ),
			array( '%s' ),
			array( '%d' )
		);

		if ( false !== $updated ) {
			wp_send_json_success( array( 'message' => __( 'Alert dismissed.', 'wp-sentinel-security' ) ) );
		} else {
			wp_send_json_error( array( 'message' => __( 'Failed to dismiss alert.', 'wp-sentinel-security' ) ) );
		}
	}
}
