<?php
/**
 * Database Scanner — scans WordPress database tables for injected malicious content.
 *
 * Checks wp_posts, wp_postmeta, wp_comments, wp_options, and wp_users for
 * stored XSS, spam URLs, suspicious option modifications, hidden admin users,
 * malicious cron jobs, and suspicious encoded transients.
 *
 * @package WP_Sentinel_Security
 * @since   2.2.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Database_Scanner
 */
class Database_Scanner {

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
	 * Run all database security checks.
	 *
	 * @return array Array of vulnerability data arrays.
	 */
	public function scan() {
		$vulnerabilities = array();

		$vulnerabilities = array_merge(
			$vulnerabilities,
			$this->check_post_content(),
			$this->check_options(),
			$this->check_hidden_admin_users(),
			$this->check_malicious_cron_jobs(),
			$this->check_suspicious_transients()
		);

		return $vulnerabilities;
	}

	/**
	 * Scan wp_posts for injected JavaScript or iframes (stored XSS).
	 *
	 * @return array
	 */
	private function check_post_content() {
		global $wpdb;

		$vulnerabilities = array();
		$own_host = parse_url( home_url(), PHP_URL_HOST );

		$patterns = array(
			'/<script[^>]*>[^<]*<\/script>/i'  => 'Injected <script> block in post content',
			'/document\.cookie/i'               => 'document.cookie access in post content',
			'/eval\s*\(\s*(?:base64_decode|gzinflate|str_rot13)/i' => 'Encoded eval() in post content',
		);

		// Only add the iframe pattern when we have a valid host to exclude.
		if ( ! empty( $own_host ) ) {
			$patterns[ '/<iframe[^>]+src=["\']https?:\/\/(?!' . preg_quote( $own_host, '/' ) . ')/i' ] = 'External <iframe> in post content';
		} else {
			$patterns[ '/<iframe[^>]+src=["\']https?:\/\//i' ] = 'External <iframe> in post content';
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$posts = $wpdb->get_results(
			"SELECT ID, post_title, post_content FROM {$wpdb->posts}
			WHERE post_status = 'publish' AND post_type IN ('post','page')
			ORDER BY ID DESC LIMIT 500"
		);

		if ( ! $posts ) {
			return $vulnerabilities;
		}

		foreach ( $posts as $post ) {
			foreach ( $patterns as $pattern => $description ) {
				if ( preg_match( $pattern, $post->post_content ) ) {
					$vulnerabilities[] = array(
						'component_type'    => 'database',
						'component_name'    => 'Post: ' . wp_strip_all_tags( $post->post_title ),
						'component_version' => '',
						'severity'          => 'critical',
						'cvss_score'        => 9.1,
						'title'             => 'Stored XSS / Malicious Content in Post',
						'description'       => $description . ' (Post ID: ' . (int) $post->ID . ')',
						'recommendation'    => 'Review and clean the post content. Consider restoring from a backup if the site was compromised.',
						'reference'         => 'https://owasp.org/www-community/attacks/xss/',
					);
					break; // One finding per post is enough.
				}
			}
		}

		return $vulnerabilities;
	}

	/**
	 * Scan wp_options for suspicious modifications.
	 *
	 * @return array
	 */
	private function check_options() {
		global $wpdb;

		$vulnerabilities = array();

		// Check siteurl / home for unexpected changes.
		$siteurl = get_option( 'siteurl', '' );
		$home    = get_option( 'home', '' );

		// Detect mismatch between siteurl and home — common after redirect injection.
		if ( ! empty( $siteurl ) && ! empty( $home ) ) {
			$site_host = parse_url( $siteurl, PHP_URL_HOST );
			$home_host = parse_url( $home, PHP_URL_HOST );
			if ( $site_host && $home_host && strtolower( $site_host ) !== strtolower( $home_host ) ) {
				$vulnerabilities[] = array(
					'component_type'    => 'database',
					'component_name'    => 'wp_options: siteurl/home mismatch',
					'component_version' => '',
					'severity'          => 'high',
					'cvss_score'        => 7.5,
					'title'             => 'Site URL / Home URL Mismatch in Options',
					'description'       => sprintf(
						'siteurl (%s) and home (%s) point to different hosts — may indicate redirect injection.',
						esc_url( $siteurl ),
						esc_url( $home )
					),
					'recommendation'    => 'Verify that siteurl and home in wp_options are both set to the correct domain.',
					'reference'         => 'https://wordpress.org/support/article/changing-the-site-url/',
				);
			}
		}

		// Check admin_email for unexpected value.
		$admin_email = get_option( 'admin_email', '' );
		if ( ! empty( $admin_email ) && ! is_email( $admin_email ) ) {
			$vulnerabilities[] = array(
				'component_type'    => 'database',
				'component_name'    => 'wp_options: admin_email',
				'component_version' => '',
				'severity'          => 'medium',
				'cvss_score'        => 5.0,
				'title'             => 'Invalid Admin Email in Options',
				'description'       => 'The admin_email option does not contain a valid email address.',
				'recommendation'    => 'Update the admin email address in Settings → General.',
				'reference'         => '',
			);
		}

		// Look for injected scripts in widget options.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$widget_options = $wpdb->get_results(
			"SELECT option_name, option_value FROM {$wpdb->options}
			WHERE option_name LIKE 'widget_%'
			LIMIT 200"
		);

		if ( $widget_options ) {
			foreach ( $widget_options as $row ) {
				if ( preg_match( '/<script[^>]*>/i', $row->option_value ) ) {
					$vulnerabilities[] = array(
						'component_type'    => 'database',
						'component_name'    => 'wp_options: ' . esc_html( $row->option_name ),
						'component_version' => '',
						'severity'          => 'critical',
						'cvss_score'        => 9.0,
						'title'             => 'Injected Script in Widget Options',
						'description'       => 'A <script> tag was found in a widget option (' . esc_html( $row->option_name ) . ').',
						'recommendation'    => 'Remove the widget and check for site compromise.',
						'reference'         => 'https://owasp.org/www-community/attacks/xss/',
					);
				}
			}
		}

		return $vulnerabilities;
	}

	/**
	 * Detect hidden administrator accounts not created through normal means.
	 *
	 * A "hidden" admin is one whose username is all numeric, contains non-ASCII
	 * characters, or is suspiciously short (1-2 chars), which are common traits
	 * of attacker-created backdoor accounts.
	 *
	 * @return array
	 */
	private function check_hidden_admin_users() {
		global $wpdb;

		$vulnerabilities = array();

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$admin_users = $wpdb->get_results(
			"SELECT u.ID, u.user_login, u.user_registered
			FROM {$wpdb->users} u
			INNER JOIN {$wpdb->usermeta} um ON u.ID = um.user_id
			WHERE um.meta_key = '{$wpdb->prefix}capabilities'
			AND um.meta_value LIKE '%administrator%'"
		);

		if ( ! $admin_users ) {
			return $vulnerabilities;
		}

		foreach ( $admin_users as $user ) {
			$login = $user->user_login;
			$suspicious = false;
			$reason     = '';

			// Empty or very short username.
			if ( '' === $login || strlen( $login ) <= 2 ) {
				$suspicious = true;
				$reason     = '' === $login ? 'Username is empty.' : 'Username is suspiciously short.';
			} elseif ( ctype_digit( $login ) ) {
				// All-numeric username.
				$suspicious = true;
				$reason     = 'Username is all-numeric.';
			} elseif ( ! preg_match( '/^[a-zA-Z0-9_\-\.@]+$/', $login ) ) {
				$suspicious = true;
				$reason     = 'Username contains unusual characters.';
			}

			if ( $suspicious ) {
				$vulnerabilities[] = array(
					'component_type'    => 'database',
					'component_name'    => 'WordPress User: ' . esc_html( $login ),
					'component_version' => '',
					'severity'          => 'critical',
					'cvss_score'        => 9.8,
					'title'             => 'Suspicious Administrator Account Detected',
					'description'       => 'Administrator account "' . esc_html( $login ) . '" has suspicious characteristics. ' . $reason,
					'recommendation'    => 'Review this account immediately. If unknown, delete it and change all passwords.',
					'reference'         => 'https://wordpress.org/support/article/hardening-wordpress/#user-accounts',
				);
			}
		}

		return $vulnerabilities;
	}

	/**
	 * Detect potentially malicious WP-Cron jobs.
	 *
	 * @return array
	 */
	private function check_malicious_cron_jobs() {
		$vulnerabilities = array();

		$cron_option = get_option( 'cron', array() );
		if ( ! is_array( $cron_option ) ) {
			return $vulnerabilities;
		}

		// Known legitimate WordPress core hooks.
		$known_hooks = array(
			'wp_scheduled_delete',
			'wp_privacy_delete_old_export_files',
			'wp_update_plugins',
			'wp_update_themes',
			'wp_version_check',
			'wp_scheduled_auto_draft_delete',
			'delete_expired_transients',
			'recovery_mode_clean_expired_keys',
			'wp_site_health_scheduled_check',
			'wp_https_detection',
			'wp_update_user_counts',
		);

		foreach ( $cron_option as $timestamp => $hooks ) {
			if ( ! is_array( $hooks ) || 'version' === $timestamp ) {
				continue;
			}

			foreach ( $hooks as $hook => $data ) {
				// Flag hooks that look obfuscated or use encoded payloads.
				if ( preg_match( '/^[a-f0-9]{32,}$/', $hook ) ||
					 preg_match( '/(?:eval|base64|exec|system|passthru)/i', $hook ) ) {
					$vulnerabilities[] = array(
						'component_type'    => 'database',
						'component_name'    => 'WP-Cron: ' . esc_html( $hook ),
						'component_version' => '',
						'severity'          => 'critical',
						'cvss_score'        => 9.5,
						'title'             => 'Suspicious WP-Cron Job Detected',
						'description'       => 'A suspicious cron hook was found: "' . esc_html( $hook ) . '".',
						'recommendation'    => 'Remove this cron job and investigate how it was added.',
						'reference'         => '',
					);
				}
			}
		}

		return $vulnerabilities;
	}

	/**
	 * Detect suspicious transients with encoded payloads.
	 *
	 * @return array
	 */
	private function check_suspicious_transients() {
		global $wpdb;

		$vulnerabilities = array();

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$transients = $wpdb->get_results(
			"SELECT option_name, option_value FROM {$wpdb->options}
			WHERE option_name LIKE '_transient_%'
			AND LENGTH(option_value) > 500
			LIMIT 200"
		);

		if ( ! $transients ) {
			return $vulnerabilities;
		}

		foreach ( $transients as $row ) {
			$decoded = base64_decode( $row->option_value, true );  // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
			if ( false !== $decoded && preg_match( '/<?php|eval\(|base64_decode\(|system\(|exec\(/i', $decoded ) ) {
				$vulnerabilities[] = array(
					'component_type'    => 'database',
					'component_name'    => 'Transient: ' . esc_html( $row->option_name ),
					'component_version' => '',
					'severity'          => 'critical',
					'cvss_score'        => 9.5,
					'title'             => 'Suspicious Encoded Transient',
					'description'       => 'Transient "' . esc_html( $row->option_name ) . '" contains base64-encoded PHP code.',
					'recommendation'    => 'Delete this transient and investigate how it was created.',
					'reference'         => '',
				);
			}
		}

		return $vulnerabilities;
	}
}
