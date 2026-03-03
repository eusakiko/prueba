<?php
/**
 * Telegram alert channel.
 *
 * Sends Markdown-formatted messages via the Telegram Bot API.
 *
 * @package WP_Sentinel_Security
 * @since   2.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Alert_Telegram
 */
class Alert_Telegram {

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
	 * Send an alert message via Telegram Bot API.
	 *
	 * @param string $subject Short title for the alert.
	 * @param string $message Alert detail message.
	 * @param array  $data    Optional extra data: severity.
	 * @return true|WP_Error True on success, WP_Error on failure.
	 */
	public function send( $subject, $message, $data = array() ) {
		$bot_token = sanitize_text_field( $this->settings['telegram_bot_token'] ?? '' );
		$chat_id   = sanitize_text_field( $this->settings['telegram_chat_id'] ?? '' );

		if ( empty( $bot_token ) || empty( $chat_id ) ) {
			return new WP_Error( 'telegram_not_configured', __( 'Telegram bot token or chat ID is not configured.', 'wp-sentinel-security' ) );
		}

		$severity = sanitize_text_field( $data['severity'] ?? 'info' );

		$emoji_map = array(
			'critical' => '🔴',
			'high'     => '🟠',
			'medium'   => '🟡',
			'low'      => '🟢',
			'info'     => '🔵',
		);
		$emoji = $emoji_map[ $severity ] ?? '🔵';

		$site_name = get_bloginfo( 'name' );
		$site_url  = get_site_url();
		$dashboard = admin_url( 'admin.php?page=sentinel-security' );

		$text = sprintf(
			"%s *WP Sentinel Security Alert*\n\n*%s*\n\n%s\n\n🌐 *Site:* %s\n⚠️ *Severity:* %s\n\n[View Dashboard](%s)",
			$emoji,
			sanitize_text_field( $subject ),
			sanitize_text_field( $message ),
			esc_url( $site_url ),
			ucfirst( $severity ),
			esc_url( $dashboard )
		);

		$api_url = 'https://api.telegram.org/bot' . rawurlencode( $bot_token ) . '/sendMessage';

		$response = wp_remote_post(
			$api_url,
			array(
				'headers'     => array( 'Content-Type' => 'application/json' ),
				'body'        => wp_json_encode(
					array(
						'chat_id'    => $chat_id,
						'text'       => $text,
						'parse_mode' => 'Markdown',
					)
				),
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
				'telegram_http_error',
				sprintf(
					/* translators: %d: HTTP status code */
					__( 'Telegram API returned HTTP %d.', 'wp-sentinel-security' ),
					$code
				)
			);
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( empty( $body['ok'] ) ) {
			return new WP_Error(
				'telegram_api_error',
				sanitize_text_field( $body['description'] ?? __( 'Unknown Telegram API error.', 'wp-sentinel-security' ) )
			);
		}

		return true;
	}
}
