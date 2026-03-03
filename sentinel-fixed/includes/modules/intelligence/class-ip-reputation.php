<?php
/**
 * IP Reputation & Threat Feed.
 *
 * Downloads and caches known malicious IP lists. Scores incoming IPs based
 * on reputation and integrates with the WAF to auto-block low-reputation IPs.
 *
 * @package WP_Sentinel_Security
 * @since   2.2.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class IP_Reputation
 */
class IP_Reputation {

	/**
	 * Transient key for cached IP reputation list.
	 *
	 * @var string
	 */
	const TRANSIENT_KEY = 'sentinel_ip_reputation_list';

	/**
	 * Transient TTL in seconds (1 hour).
	 *
	 * @var int
	 */
	const TTL = 3600;

	/**
	 * Option key for user-agent blacklist.
	 *
	 * @var string
	 */
	const UA_BLACKLIST_OPTION = 'sentinel_ua_blacklist';

	/**
	 * Reputation score threshold below which IPs are auto-blocked.
	 *
	 * @var int
	 */
	const BLOCK_THRESHOLD = 30;

	/**
	 * Public threat feed URL (Emerging Threats blocklist format).
	 *
	 * @var string
	 */
	const FEED_URL = 'https://iplists.firehol.org/files/firehol_level1.netset';

	/**
	 * Plugin settings.
	 *
	 * @var array
	 */
	private $settings;

	/**
	 * IP_Manager instance.
	 *
	 * @var IP_Manager|null
	 */
	private $ip_manager;

	/**
	 * Default known-malicious user-agent patterns.
	 *
	 * @var string[]
	 */
	private static $default_ua_patterns = array(
		'/nikto/i',
		'/sqlmap/i',
		'/nessus/i',
		'/nmap/i',
		'/masscan/i',
		'/zgrab/i',
		'/python-requests\/[01]\./i',
		'/curl\/[0-6]\./i',
		'/go-http-client\/1\./i',
		'/libwww-perl/i',
		'/harvest/i',
		'/dirbuster/i',
		'/gobuster/i',
		'/wfuzz/i',
	);

	/**
	 * Constructor.
	 *
	 * @param array      $settings   Plugin settings.
	 * @param IP_Manager $ip_manager Optional IP_Manager instance.
	 */
	public function __construct( $settings = array(), $ip_manager = null ) {
		$this->settings   = $settings;
		$this->ip_manager = $ip_manager;
	}

	/**
	 * Initialize — register WP-Cron hook to refresh feed hourly.
	 *
	 * @return void
	 */
	public function init() {
		add_action( 'sentinel_refresh_ip_reputation', array( $this, 'refresh_feed' ) );

		if ( ! wp_next_scheduled( 'sentinel_refresh_ip_reputation' ) ) {
			wp_schedule_event( time(), 'hourly', 'sentinel_refresh_ip_reputation' );
		}
	}

	/**
	 * Score an IP address based on reputation.
	 *
	 * @param string $ip IP address to score.
	 * @return int Score 0–100 (0 = worst, 100 = clean).
	 */
	public function get_score( $ip ) {
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return 100;
		}

		$blacklist = $this->get_cached_blacklist();

		foreach ( $blacklist as $entry ) {
			if ( false !== strpos( $entry, '/' ) ) {
				// CIDR entry.
				if ( $this->ip_manager && $this->ip_manager->ip_in_cidr( $ip, $entry ) ) {
					return 0;
				}
			} elseif ( $ip === $entry ) {
				return 0;
			}
		}

		return 100;
	}

	/**
	 * Check if a given user-agent matches a known malicious bot pattern.
	 *
	 * @param string $user_agent User-Agent string.
	 * @return bool True if the UA is blacklisted.
	 */
	public function is_bad_bot( $user_agent ) {
		if ( empty( $user_agent ) ) {
			return false;
		}

		$custom = get_option( self::UA_BLACKLIST_OPTION, array() );
		$patterns = is_array( $custom ) ? array_merge( self::$default_ua_patterns, $custom ) : self::$default_ua_patterns;

		foreach ( $patterns as $pattern ) {
			if ( @preg_match( $pattern, $user_agent ) ) {  // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
				return true;
			}
		}

		return false;
	}

	/**
	 * Evaluate an incoming request and auto-block if reputation is poor.
	 *
	 * Call this from the WAF's inspect_request() method.
	 *
	 * @param string $ip         Client IP address.
	 * @param string $user_agent Client user-agent string.
	 * @return bool True if the request should be blocked.
	 */
	public function should_block( $ip, $user_agent = '' ) {
		if ( $this->is_bad_bot( $user_agent ) ) {
			return true;
		}

		$score = $this->get_score( $ip );
		if ( $score < self::BLOCK_THRESHOLD ) {
			if ( $this->ip_manager ) {
				$this->ip_manager->block_ip( $ip, 'Auto-blocked: low IP reputation score (' . $score . ')', time() + HOUR_IN_SECONDS );
			}
			return true;
		}

		return false;
	}

	/**
	 * Refresh the IP reputation feed and cache it.
	 *
	 * Fetches from the configured feed URL and stores as a transient.
	 *
	 * @return bool True on success.
	 */
	public function refresh_feed() {
		$response = wp_remote_get(
			self::FEED_URL,
			array(
				'timeout'   => 15,
				'sslverify' => true,
			)
		);

		if ( is_wp_error( $response ) ) {
			return false;
		}

		$body = wp_remote_retrieve_body( $response );
		if ( empty( $body ) ) {
			return false;
		}

		$lines = explode( "\n", $body );
		$ips   = array();

		foreach ( $lines as $line ) {
			$line = trim( $line );
			// Skip empty lines and comment lines (starting with '#').
			if ( '' === $line || '#' === substr( $line, 0, 1 ) ) {
				continue;
			}
			// Accept plain IPs and CIDR ranges.
			if ( filter_var( $line, FILTER_VALIDATE_IP ) || $this->is_valid_cidr( $line ) ) {
				$ips[] = $line;
			}
		}

		if ( ! empty( $ips ) ) {
			set_transient( self::TRANSIENT_KEY, $ips, self::TTL );
			return true;
		}

		return false;
	}

	/**
	 * Get the cached IP blacklist (or an empty array if not yet loaded).
	 *
	 * @return string[]
	 */
	public function get_cached_blacklist() {
		$cached = get_transient( self::TRANSIENT_KEY );
		return is_array( $cached ) ? $cached : array();
	}

	/**
	 * Add a custom user-agent pattern to the blacklist.
	 *
	 * @param string $pattern Regex pattern (including delimiters).
	 * @return bool True on success.
	 */
	public function add_ua_pattern( $pattern ) {
		$list   = get_option( self::UA_BLACKLIST_OPTION, array() );
		$list   = is_array( $list ) ? $list : array();
		$list[] = sanitize_text_field( $pattern );
		return update_option( self::UA_BLACKLIST_OPTION, array_unique( $list ) );
	}

	/**
	 * Validate a CIDR notation string.
	 *
	 * @param string $cidr CIDR string.
	 * @return bool True if valid IPv4 CIDR.
	 */
	private function is_valid_cidr( $cidr ) {
		$parts = explode( '/', $cidr, 2 );
		if ( 2 !== count( $parts ) ) {
			return false;
		}
		$mask = (int) $parts[1];
		return filter_var( $parts[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 )
			&& $mask >= 0 && $mask <= 32;
	}
}
