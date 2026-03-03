<?php
/**
 * Slack alert channel.
 *
 * Sends Block Kit payloads to a Slack incoming webhook.
 *
 * @package WP_Sentinel_Security
 * @since   2.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Alert_Slack
 */
class Alert_Slack {

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
	 * Send an alert to Slack via webhook.
	 *
	 * @param string $subject Short title for the alert.
	 * @param string $message Alert detail message.
	 * @param array  $data    Optional extra data: severity.
	 * @return true|WP_Error True on success, WP_Error on failure.
	 */
	public function send( $subject, $message, $data = array() ) {
		$webhook_url = esc_url_raw( $this->settings['slack_webhook'] ?? '' );

		if ( empty( $webhook_url ) ) {
			return new WP_Error( 'slack_no_webhook', __( 'Slack webhook URL is not configured.', 'wp-sentinel-security' ) );
		}

		$severity = sanitize_text_field( $data['severity'] ?? 'info' );

		$severity_colors = array(
			'critical' => '#dc2626',
			'high'     => '#ea580c',
			'medium'   => '#ca8a04',
			'low'      => '#16a34a',
			'info'     => '#2563eb',
		);
		$color = $severity_colors[ $severity ] ?? '#2563eb';

		$site_name = get_bloginfo( 'name' );
		$site_url  = get_site_url();

		$payload = array(
			'blocks' => array(
				array(
					'type' => 'header',
					'text' => array(
						'type'  => 'plain_text',
						'text'  => '🔒 WP Sentinel Security Alert',
						'emoji' => true,
					),
				),
				array(
					'type' => 'section',
					'text' => array(
						'type' => 'mrkdwn',
						'text' => '*' . $this->slack_escape( $subject ) . '*',
					),
				),
				array(
					'type' => 'section',
					'text' => array(
						'type' => 'mrkdwn',
						'text' => $this->slack_escape( $message ),
					),
					'fields' => array(
						array(
							'type' => 'mrkdwn',
							'text' => '*Site:*\n' . esc_url( $site_url ),
						),
						array(
							'type' => 'mrkdwn',
							'text' => '*Severity:*\n' . ucfirst( $severity ),
						),
					),
				),
				array(
					'type'     => 'actions',
					'elements' => array(
						array(
							'type'  => 'button',
							'text'  => array(
								'type'  => 'plain_text',
								'text'  => 'View Dashboard',
								'emoji' => true,
							),
							'url'   => esc_url( admin_url( 'admin.php?page=sentinel-security' ) ),
							'style' => 'primary',
						),
					),
				),
			),
			'attachments' => array(
				array(
					'color'    => $color,
					'fallback' => $this->slack_escape( $subject ) . ' — ' . $this->slack_escape( $message ),
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
		if ( 200 !== (int) $code ) {
			return new WP_Error(
				'slack_http_error',
				sprintf(
					/* translators: %d: HTTP status code */
					__( 'Slack returned HTTP %d.', 'wp-sentinel-security' ),
					$code
				)
			);
		}

		return true;
	}
	private function slack_escape( $text ) {
		$text = sanitize_text_field( (string) $text );
		return strtr( $text, array( "&" => "&amp;", "<" => "&lt;", ">" => "&gt;", "*" => "â*", "_" => "â_", "~" => "â~", chr(96) => "â" + chr(96) ) );
	}

}
