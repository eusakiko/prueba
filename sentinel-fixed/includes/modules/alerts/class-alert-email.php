<?php
/**
 * Email alert channel.
 *
 * Sends HTML alert emails via wp_mail().
 *
 * @package WP_Sentinel_Security
 * @since   2.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Alert_Email
 */
class Alert_Email {

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
	 * Send an HTML alert email.
	 *
	 * @param string $subject Email subject.
	 * @param string $message Plain-text message body (will be wrapped in HTML template).
	 * @param array  $data    Optional extra data: severity, action_url.
	 * @return bool True on success, false on failure.
	 */
	public function send( $subject, $message, $data = array() ) {
		$raw_email = $this->settings['alert_email'] ?? get_option( 'alert_email' );
		if ( empty( $raw_email ) ) {
			$raw_email = get_option( 'admin_email' );
		}

		// Support comma-separated recipients.
		$recipients = array_filter(
			array_map( 'sanitize_email', array_map( 'trim', explode( ',', $raw_email ) ) )
		);

		if ( empty( $recipients ) ) {
			return false;
		}

		$severity   = sanitize_text_field( $data['severity'] ?? 'info' );
		$action_url = esc_url( $data['action_url'] ?? admin_url( 'admin.php?page=sentinel-security' ) );

		$severity_colors = array(
			'critical' => '#dc2626',
			'high'     => '#ea580c',
			'medium'   => '#ca8a04',
			'low'      => '#16a34a',
			'info'     => '#2563eb',
		);
		$header_color = $severity_colors[ $severity ] ?? '#4f46e5';

		$html_message = $this->build_template( $subject, $message, $severity, $header_color, $action_url );

		add_filter( 'wp_mail_content_type', array( $this, 'set_html_content_type' ) );

		$sent = wp_mail( $recipients, sanitize_text_field( $subject ), $html_message );

		remove_filter( 'wp_mail_content_type', array( $this, 'set_html_content_type' ) );

		return $sent;
	}

	/**
	 * Set email content type to HTML.
	 *
	 * @return string
	 */
	public function set_html_content_type() {
		return 'text/html';
	}

	/**
	 * Build the HTML email template.
	 *
	 * @param string $subject      Email subject.
	 * @param string $message      Alert message.
	 * @param string $severity     Severity label.
	 * @param string $header_color Hex color for the header bar.
	 * @param string $action_url   URL for the action button.
	 * @return string HTML email string.
	 */
	private function build_template( $subject, $message, $severity, $header_color, $action_url ) {
		$site_name    = esc_html( get_bloginfo( 'name' ) );
		$subject_html = esc_html( $subject );
		$message_html = nl2br( esc_html( $message ) );
		$severity_uc  = esc_html( ucfirst( $severity ) );
		$action_url   = esc_url( $action_url );
		$header_color = esc_attr( preg_match( '/^#[0-9a-fA-F]{6}$/', $header_color ) ? $header_color : '#4f46e5' );
		$year         = esc_html( gmdate( 'Y' ) );

		return <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>{$subject_html}</title>
</head>
<body style="margin:0;padding:0;background:#f1f5f9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f1f5f9;padding:32px 0;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.08);">
  <!-- Header -->
  <tr>
    <td style="background:{$header_color};padding:28px 32px;text-align:center;">
      <h1 style="margin:0;color:#fff;font-size:20px;font-weight:700;">WP Sentinel Security</h1>
      <p style="margin:6px 0 0;color:rgba(255,255,255,.85);font-size:13px;">{$subject_html}</p>
    </td>
  </tr>
  <!-- Severity badge -->
  <tr>
    <td style="padding:16px 32px 0;text-align:center;">
      <span style="display:inline-block;background:{$header_color};color:#fff;padding:4px 14px;border-radius:99px;font-size:12px;font-weight:700;text-transform:uppercase;">{$severity_uc}</span>
    </td>
  </tr>
  <!-- Body -->
  <tr>
    <td style="padding:24px 32px;font-size:14px;color:#334155;line-height:1.7;">
      {$message_html}
    </td>
  </tr>
  <!-- Action button -->
  <tr>
    <td style="padding:0 32px 28px;text-align:center;">
      <a href="{$action_url}" style="display:inline-block;background:{$header_color};color:#fff;padding:12px 28px;border-radius:6px;font-size:14px;font-weight:600;text-decoration:none;">
        View Dashboard
      </a>
    </td>
  </tr>
  <!-- Footer -->
  <tr>
    <td style="background:#f8fafc;border-top:1px solid #e2e8f0;padding:16px 32px;text-align:center;font-size:11px;color:#94a3b8;">
      &copy; {$year} {$site_name} &mdash; WP Sentinel Security Plugin
    </td>
  </tr>
</table>
</td></tr>
</table>
</body>
</html>
HTML;
	}
}
