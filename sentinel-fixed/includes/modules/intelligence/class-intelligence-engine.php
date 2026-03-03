<?php
/**
 * Intelligence Engine — Orchestrator for the Intelligence Layer.
 *
 * @package WP_Sentinel_Security
 * @since   1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Intelligence_Engine
 */
class Intelligence_Engine {

	/**
	 * Plugin settings.
	 *
	 * @var array
	 */
	private $settings;

	/**
	 * Context Analyzer sub-module.
	 *
	 * @var Context_Analyzer
	 */
	private $context_analyzer;

	/**
	 * Environment Fingerprint sub-module.
	 *
	 * @var Environment_Fingerprint
	 */
	private $environment_fingerprint;

	/**
	 * Attack Surface Mapper sub-module.
	 *
	 * @var Attack_Surface_Mapper
	 */
	private $attack_surface_mapper;

	/**
	 * Risk Context Score sub-module.
	 *
	 * @var Risk_Context_Score
	 */
	private $risk_context_score;

	/**
	 * Transient cache key for intelligence data.
	 */
	const CACHE_KEY = 'sentinel_intelligence_data';

	/**
	 * Cache duration: 12 hours in seconds.
	 */
	const CACHE_TTL = 43200;

	/**
	 * Constructor.
	 *
	 * @param array $settings Plugin settings.
	 */
	public function __construct( $settings = array() ) {
		$this->settings = $settings;
	}

	/**
	 * Initialise sub-modules and register hooks.
	 *
	 * @return void
	 */
	public function init() {
		// Load sub-module files.
		$dir = SENTINEL_PLUGIN_DIR . 'includes/modules/intelligence/';
		require_once $dir . 'class-context-analyzer.php';
		require_once $dir . 'class-environment-fingerprint.php';
		require_once $dir . 'class-attack-surface-mapper.php';
		require_once $dir . 'class-risk-context-score.php';

		// Instantiate sub-modules.
		$this->context_analyzer        = new Context_Analyzer();
		$this->environment_fingerprint = new Environment_Fingerprint();
		$this->attack_surface_mapper   = new Attack_Surface_Mapper();
		$this->risk_context_score      = new Risk_Context_Score();

		// AJAX handler.
		add_action( 'wp_ajax_sentinel_run_intelligence', array( $this, 'ajax_run_intelligence' ) );

		// Hook into post-scan processing.
		add_action( 'sentinel_post_scan_analysis', array( $this, 'enrich_scan_results' ), 10, 2 );
	}

	/**
	 * Run the full intelligence analysis pipeline.
	 *
	 * Results are cached in a transient for 12 hours.
	 * Pass $force = true to bypass cache.
	 *
	 * @param bool $force Force fresh analysis even if cached.
	 * @return array Intelligence data.
	 */
	public function run_full_analysis( $force = false ) {
		if ( ! $force ) {
			$cached = get_transient( self::CACHE_KEY );
			if ( false !== $cached ) {
				return $cached;
			}
		}

		$environment   = $this->environment_fingerprint->fingerprint();
		$attack_surface = $this->attack_surface_mapper->map();

		$data = array(
			'timestamp'      => current_time( 'mysql' ),
			'environment'    => $environment,
			'attack_surface' => $attack_surface,
			'context'        => array(),
		);

		set_transient( self::CACHE_KEY, $data, self::CACHE_TTL );

		return $data;
	}

	/**
	 * Enrich a completed scan's vulnerabilities with intelligence context scores.
	 *
	 * Hooked to `sentinel_post_scan_analysis`.
	 *
	 * @param array $scan_results Raw array of vulnerability records.
	 * @param int   $scan_id      Scan row ID.
	 * @return void
	 */
	public function enrich_scan_results( $scan_results, $scan_id ) {
		global $wpdb;

		$intelligence = $this->run_full_analysis();

		foreach ( $scan_results as $vulnerability ) {
			$vuln_array = (array) $vulnerability;
			$context    = $this->context_analyzer->analyze_vulnerability( $vuln_array, $intelligence );
			$score_data = $this->risk_context_score->calculate( $vuln_array, $context, $intelligence );

			// Persist context score back to the vulnerability record.
			if ( ! empty( $vuln_array['id'] ) ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
				$wpdb->update(
					"{$wpdb->prefix}sentinel_vulnerabilities",
					array(
						'cvss_score' => $score_data['final_score'],
						'severity'   => $score_data['adjusted_severity'],
					),
					array( 'id' => absint( $vuln_array['id'] ) ),
					array( '%f', '%s' ),
					array( '%d' )
				);
			}
		}
	}

	/**
	 * AJAX handler: run a fresh intelligence analysis.
	 *
	 * @return void
	 */
	public function ajax_run_intelligence() {
		check_ajax_referer( 'sentinel_intelligence_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'wp-sentinel-security' ) ), 403 );
		}

		$data = $this->run_full_analysis( true );

		wp_send_json_success( $data );
	}
}
