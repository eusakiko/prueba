<?php
/**
 * External Blacklist Monitor.
 *
 * Checks the site against Google Safe Browsing, SpamHaus DBL, and
 * PhishTank and sends an immediate alert if the site appears on any list.
 *
 * @package WP_Sentinel_Security
 * @since   2.2.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Blacklist_Monitor
 */
class Blacklist_Monitor {

	/**
	 * Transient key for cached check results.
	 *
	 * @var string
	 */
	const TRANSIENT_KEY = 'sentinel_blacklist_status';

	/**
	 * Transient TTL in seconds (6 hours).
	 *
	 * @var int
	 */
	const TTL = 21600;

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
	 * Initialize — register WP-Cron hook for scheduled checks.
	 *
	 * @return void
	 */
	public function init() {
		add_action( 'sentinel_blacklist_check', array( $this, 'run_check' ) );
	}

	/**
	 * Run all blacklist checks and return the combined status.
	 *
	 * Results are cached for TTL seconds. If any service lists the site,
	 * an alert is dispatched immediately.
	 *
	 * @param bool $force Force a fresh check (skip cache).
	 * @return array Status array keyed by service name.
	 */
	public function run_check( $force = false ) {
		if ( ! $force ) {
			$cached = get_transient( self::TRANSIENT_KEY );
			if ( false !== $cached ) {
				return $cached;
			}
		}

		$host    = parse_url( home_url(), PHP_URL_HOST );
		$results = array();

		$results['google_safe_browsing'] = $this->check_google_safe_browsing( $host );
		$results['spamhaus_dbl']         = $this->check_spamhaus_dbl( $host );
		$results['phishtank']            = $this->check_phishtank( home_url() );

		set_transient( self::TRANSIENT_KEY, $results, self::TTL );

		// Alert if any service reports a positive listing.
		$blacklisted_by = array();
		foreach ( $results as $service => $status ) {
			if ( isset( $status['listed'] ) && true === $status['listed'] ) {
				$blacklisted_by[] = $service;
			}
		}

		if ( ! empty( $blacklisted_by ) ) {
			do_action(
				'sentinel_send_alert',
				__( '🚨 Site Listed on External Blacklist', 'wp-sentinel-security' ),
				sprintf(
					__( 'WP Sentinel has detected that %s appears on the following blacklists: %s. Immediate action required.', 'wp-sentinel-security' ),
					esc_url( home_url() ),
					implode( ', ', array_map( 'sanitize_text_field', $blacklisted_by ) )
				),
				array( 'severity' => 'critical', 'event_type' => 'blacklist_detected' )
			);
		}

		return $results;
	}

	/**
	 * Get the cached blacklist status without running a fresh check.
	 *
	 * @return array|false Cached results or false if not available.
	 */
	public function get_cached_status() {
		return get_transient( self::TRANSIENT_KEY );
	}

	/**
	 * Check Google Safe Browsing API.
	 *
	 * @param string $host Hostname to check.
	 * @return array [ 'listed' => bool, 'reason' => string, 'checked_at' => int ]
	 */
	private function check_google_safe_browsing( $host ) {
		$api_key = $this->settings['google_safe_browsing_key'] ?? '';

		if ( empty( $api_key ) ) {
			return array( 'listed' => false, 'reason' => 'No API key configured', 'checked_at' => time() );
		}

		// Build the URL from the hostname to be consistent with the $host parameter.
		$scheme    = is_ssl() ? 'https' : 'http';
		$check_url = $scheme . '://' . $host . '/';

		$url  = 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' . rawurlencode( $api_key );
		$body = wp_json_encode(
			array(
				'client'     => array(
					'clientId'      => 'wp-sentinel-security',
					'clientVersion' => SENTINEL_VERSION,
				),
				'threatInfo' => array(
					'threatTypes'      => array( 'MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'THREAT_TYPE_UNSPECIFIED' ),
					'platformTypes'    => array( 'ANY_PLATFORM' ),
					'threatEntryTypes' => array( 'URL' ),
					'threatEntries'    => array( array( 'url' => $check_url ) ),
				),
			)
		);

		$response = wp_remote_post(
			$url,
			array(
				'timeout' => 10,
				'headers' => array( 'Content-Type' => 'application/json' ),
				'body'    => $body,
			)
		);

		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return array( 'listed' => false, 'reason' => 'API error', 'checked_at' => time() );
		}

		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		$listed = ! empty( $data['matches'] );

		return array(
			'listed'     => $listed,
			'reason'     => $listed ? 'Listed in Google Safe Browsing' : 'Clean',
			'checked_at' => time(),
		);
	}

	/**
	 * Check SpamHaus Domain Block List (DBL) via DNS lookup.
	 *
	 * @param string $host Hostname to check.
	 * @return array [ 'listed' => bool, 'reason' => string, 'checked_at' => int ]
	 */
	private function check_spamhaus_dbl( $host ) {
		// SpamHaus DBL: query {domain}.dbl.spamhaus.org.
		$query = $host . '.dbl.spamhaus.org';

		$result = gethostbyname( $query );

		// If the DNS lookup returns a 127.0.1.x address, the domain is listed.
		$listed = ( $result !== $query ) && preg_match( '/^127\.0\.1\./', $result );

		return array(
			'listed'     => $listed,
			'reason'     => $listed ? 'Listed in SpamHaus DBL (' . $result . ')' : 'Clean',
			'checked_at' => time(),
		);
	}

	/**
	 * Check PhishTank API.
	 *
	 * @param string $url Full URL to check.
	 * @return array [ 'listed' => bool, 'reason' => string, 'checked_at' => int ]
	 */
	private function check_phishtank( $url ) {
		$response = wp_remote_post(
			'https://checkurl.phishtank.com/checkurl/',
			array(
				'timeout' => 10,
				'body'    => array(
					'url'    => rawurlencode( $url ),
					'format' => 'json',
				),
			)
		);

		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return array( 'listed' => false, 'reason' => 'API error', 'checked_at' => time() );
		}

		$data   = json_decode( wp_remote_retrieve_body( $response ), true );
		$listed = isset( $data['results']['in_database'] ) && $data['results']['in_database'];
		$valid  = $listed && ! empty( $data['results']['valid'] );

		return array(
			'listed'     => $listed && $valid,
			'reason'     => ( $listed && $valid ) ? 'Listed in PhishTank as a phishing URL' : 'Clean',
			'checked_at' => time(),
		);
	}
}
