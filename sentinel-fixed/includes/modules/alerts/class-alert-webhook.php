<?php
/**
 * Generic webhook alert channel.
 *
 * Sends JSON payloads to a configurable webhook URL.
 * Supports custom headers for integration with third-party services
 * such as PagerDuty, OpsGenie, or custom endpoints.
 *
 * @package WP_Sentinel_Security
 * @since   2.1.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Alert_Webhook
 */
class Alert_Webhook {

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
	 * Send an alert via generic webhook.
	 *
	 * The payload contains a standardized JSON object with event, severity,
	 * site info, and timestamp — suitable for any webhook consumer.
	 *
	 * @param string $subject Short title for the alert.
	 * @param string $message Alert detail message.
	 * @param array  $data    Optional extra data: severity, event_type.
	 * @return true|WP_Error True on success, WP_Error on failure.
	 */
	public function send( $subject, $message, $data = array() ) {
		$webhook_url = esc_url_raw( $this->settings['webhook_url'] ?? '' );

		if ( empty( $webhook_url ) ) {
			return new WP_Error( 'webhook_no_url', __( 'Webhook URL is not configured.', 'wp-sentinel-security' ) );
		}

		$severity = sanitize_text_field( $data['severity'] ?? 'info' );

		$payload = array(
			'event'     => sanitize_text_field( $data['event_type'] ?? 'security_alert' ),
			'subject'   => sanitize_text_field( $subject ),
			'message'   => sanitize_text_field( $message ),
			'severity'  => $severity,
			'site_url'  => get_site_url(),
			'site_name' => get_bloginfo( 'name' ),
			'timestamp' => gmdate( 'c' ),
			'source'    => 'wp-sentinel-security',
			'version'   => SENTINEL_VERSION,
		);

		// Allow additional custom headers (e.g. API keys).
		$headers = array( 'Content-Type' => 'application/json' );

		$custom_headers = $this->settings['webhook_headers'] ?? array();
		if ( is_array( $custom_headers ) ) {
			foreach ( $custom_headers as $key => $value ) {
				$headers[ sanitize_text_field( $key ) ] = sanitize_text_field( $value );
			}
		}

		$response = wp_remote_post(
			$webhook_url,
			array(
				'headers'     => $headers,
				'body'        => wp_json_encode( $payload ),
				'timeout'     => 15,
				'data_format' => 'body',
			)
		);

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( $code < 200 || $code > 299 ) {
			return new WP_Error(
				'webhook_http_error',
				sprintf(
					/* translators: %d: HTTP status code */
					__( 'Webhook returned HTTP %d.', 'wp-sentinel-security' ),
					$code
				)
			);
		}

		return true;
	}
}
