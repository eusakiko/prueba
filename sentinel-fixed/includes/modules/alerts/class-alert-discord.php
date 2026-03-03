<?php
/**
 * Discord alert channel.
 *
 * Sends embed-formatted messages to a Discord webhook.
 *
 * @package WP_Sentinel_Security
 * @since   2.1.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Alert_Discord
 */
class Alert_Discord {

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
	 * Send an alert to Discord via webhook.
	 *
	 * @param string $subject Short title for the alert.
	 * @param string $message Alert detail message.
	 * @param array  $data    Optional extra data: severity.
	 * @return true|WP_Error True on success, WP_Error on failure.
	 */
	public function send( $subject, $message, $data = array() ) {
		$webhook_url = esc_url_raw( $this->settings['discord_webhook'] ?? '' );

		if ( empty( $webhook_url ) ) {
			return new WP_Error( 'discord_no_webhook', __( 'Discord webhook URL is not configured.', 'wp-sentinel-security' ) );
		}

		$severity = sanitize_text_field( $data['severity'] ?? 'info' );

		$severity_colors = array(
			'critical' => 0xDC2626,
			'high'     => 0xEA580C,
			'medium'   => 0xCA8A04,
			'low'      => 0x16A34A,
			'info'     => 0x2563EB,
		);
		$color = $severity_colors[ $severity ] ?? 0x2563EB;

		$site_url  = get_site_url();
		$dashboard = admin_url( 'admin.php?page=sentinel-security' );

		$payload = array(
			'embeds' => array(
				array(
					'title'       => '🔒 ' . sanitize_text_field( $subject ),
					'description' => sanitize_text_field( $message ),
					'color'       => $color,
					'fields'      => array(
						array(
							'name'   => 'Site',
							'value'  => esc_url( $site_url ),
							'inline' => true,
						),
						array(
							'name'   => 'Severity',
							'value'  => ucfirst( $severity ),
							'inline' => true,
						),
					),
					'footer'   => array(
						'text' => 'WP Sentinel Security',
					),
					'timestamp' => gmdate( 'c' ),
					'url'       => esc_url( $dashboard ),
				),
			),
		);

		$response = wp_remote_post(
			$webhook_url,
			array(
				'headers'     => array( 'Content-Type' => 'application/json' ),
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
				'discord_http_error',
				sprintf(
					/* translators: %d: HTTP status code */
					__( 'Discord returned HTTP %d.', 'wp-sentinel-security' ),
					$code
				)
			);
		}

		return true;
	}
}
