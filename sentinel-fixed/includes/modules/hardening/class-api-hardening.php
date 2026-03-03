<?php
/**
 * API Hardening — Controls WordPress API surface exposure.
 *
 * Manages option-based toggles for:
 *   - XML-RPC disabling (filter + .htaccess block)
 *   - REST API authentication enforcement
 *   - oEmbed discovery link removal
 *   - Pingback disabling
 *
 * All feature states are stored in WP options named
 * sentinel_hardening_{check_id} so they survive across requests and can
 * be toggled independently without touching wp-config.php.
 *
 * @package WP_Sentinel_Security
 * @since   2.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class API_Hardening
 *
 * Each public group exposes three methods per check:
 *   apply_*()  — activate the hardening measure and store the option
 *   revert_*() — undo the hardening measure and delete the option
 *   status_*() — report current state: array('status' => string, 'details' => string)
 *
 * Status values: 'applied' | 'not_applied' | 'partial'.
 */
class API_Hardening {

	/**
	 * Absolute path to the root .htaccess file.
	 *
	 * @var string
	 */
	private $htaccess_path;

	/**
	 * .htaccess marker label for the XML-RPC block.
	 *
	 * @var string
	 */
	const XMLRPC_MARKER = 'Sentinel-Block-XMLRPC';

	/**
	 * Constructor — resolve paths and register runtime hooks.
	 */
	public function __construct() {
		$this->htaccess_path = ABSPATH . '.htaccess';

		add_action( 'init', array( $this, 'register_runtime_hooks' ) );
	}

	/**
	 * Register WordPress filter/action hooks for currently-enabled features.
	 *
	 * Called on the 'init' action so option values are available.
	 *
	 * @return void
	 */
	public function register_runtime_hooks() {
		if ( get_option( 'sentinel_hardening_disable_xmlrpc' ) ) {
			add_filter( 'xmlrpc_enabled',  '__return_false', 100 );
			add_filter( 'xmlrpc_methods',  '__return_empty_array', 100 );
		}

		if ( get_option( 'sentinel_hardening_restrict_rest_api' ) ) {
			add_filter( 'rest_authentication_errors', array( $this, 'require_rest_authentication' ), 99 );
		}

		if ( get_option( 'sentinel_hardening_disable_oembed' ) ) {
			// Remove oEmbed discovery links from <head>.
			remove_action( 'wp_head', 'wp_oembed_add_discovery_links' );
			remove_action( 'wp_head', 'wp_oembed_add_host_js' );
			// Disable the oEmbed REST route so it cannot be queried directly.
			add_filter( 'embed_oembed_discover',    '__return_false', 100 );
			add_filter( 'oembed_response_data',      '__return_false', 100 );
			remove_action( 'rest_api_init', 'wp_oembed_register_route' );
			add_filter( 'rewrite_rules_array', array( $this, 'remove_oembed_rewrite_rules' ) );
		}

		if ( get_option( 'sentinel_hardening_disable_pingbacks' ) ) {
			add_filter( 'pre_option_default_ping_status', '__return_zero' );
			add_filter( 'xmlrpc_methods',  array( $this, 'remove_pingback_method' ), 100 );
			add_action( 'pre_ping',        array( $this, 'disable_self_ping' ) );
			add_filter( 'wp_headers',      array( $this, 'remove_x_pingback_header' ), 100 );
		}
	}

	// =========================================================================
	// 1. Disable XML-RPC
	// =========================================================================

	/**
	 * Apply: disable XML-RPC via WordPress filter and .htaccess block.
	 *
	 * @return array{status: string, message: string}
	 */
	public function disable_xmlrpc() {
		update_option( 'sentinel_hardening_disable_xmlrpc', true );

		// Also add an .htaccess block for belt-and-braces protection.
		$rules = array(
			'<Files "xmlrpc.php">',
			'    <IfModule mod_authz_core.c>',
			'        Require all denied',
			'    </IfModule>',
			'    <IfModule !mod_authz_core.c>',
			'        Order allow,deny',
			'        Deny from all',
			'    </IfModule>',
			'</Files>',
		);

		$this->write_htaccess_marker( $rules, self::XMLRPC_MARKER );

		return array(
			'status'  => 'applied',
			'message' => __( 'XML-RPC has been disabled via WordPress filters and .htaccess.', 'wp-sentinel-security' ),
		);
	}

	/**
	 * Revert: re-enable XML-RPC by removing the option and .htaccess block.
	 *
	 * @return array{status: string, message: string}
	 */
	public function revert_disable_xmlrpc() {
		delete_option( 'sentinel_hardening_disable_xmlrpc' );
		$this->remove_htaccess_marker( self::XMLRPC_MARKER );

		return array(
			'status'  => 'reverted',
			'message' => __( 'XML-RPC has been re-enabled.', 'wp-sentinel-security' ),
		);
	}

	/**
	 * Status: check whether XML-RPC is disabled.
	 *
	 * @return array{status: string, details: string}
	 */
	public function status_disable_xmlrpc() {
		$option_set = (bool) get_option( 'sentinel_hardening_disable_xmlrpc' );
		$htaccess_set = $this->htaccess_has_marker( self::XMLRPC_MARKER );

		if ( $option_set && $htaccess_set ) {
			return array(
				'status'  => 'applied',
				'details' => __( 'XML-RPC is disabled via WordPress filter and .htaccess (managed by Sentinel).', 'wp-sentinel-security' ),
			);
		}

		if ( $option_set || $htaccess_set ) {
			return array(
				'status'  => 'partial',
				'details' => __( 'XML-RPC is partially disabled (filter or .htaccess rule is missing).', 'wp-sentinel-security' ),
			);
		}

		return array(
			'status'  => 'not_applied',
			'details' => __( 'XML-RPC is enabled (WordPress default).', 'wp-sentinel-security' ),
		);
	}

	// =========================================================================
	// 2. Restrict REST API to authenticated users
	// =========================================================================

	/**
	 * Apply: require authentication for all REST API requests from public users.
	 *
	 * Core endpoints used by WordPress itself (e.g. oEmbed, block editor)
	 * remain accessible to logged-in users.
	 *
	 * @return array{status: string, message: string}
	 */
	public function restrict_rest_api() {
		update_option( 'sentinel_hardening_restrict_rest_api', true );
		return array(
			'status'  => 'applied',
			'message' => __( 'REST API access has been restricted to authenticated users.', 'wp-sentinel-security' ),
		);
	}

	/**
	 * Revert: restore public REST API access.
	 *
	 * @return array{status: string, message: string}
	 */
	public function revert_restrict_rest_api() {
		delete_option( 'sentinel_hardening_restrict_rest_api' );
		return array(
			'status'  => 'reverted',
			'message' => __( 'REST API is now accessible to all visitors (WordPress default).', 'wp-sentinel-security' ),
		);
	}

	/**
	 * Status: check whether REST API is restricted to authenticated users.
	 *
	 * @return array{status: string, details: string}
	 */
	public function status_restrict_rest_api() {
		if ( get_option( 'sentinel_hardening_restrict_rest_api' ) ) {
			return array(
				'status'  => 'applied',
				'details' => __( 'REST API requires authentication for unauthenticated requests.', 'wp-sentinel-security' ),
			);
		}
		return array(
			'status'  => 'not_applied',
			'details' => __( 'REST API is publicly accessible (WordPress default).', 'wp-sentinel-security' ),
		);
	}

	/**
	 * Filter callback: return an error for unauthenticated REST API requests.
	 *
	 * Allows requests that are already authenticated (cookie/JWT/app password).
	 * Hooked to 'rest_authentication_errors' at priority 99.
	 *
	 * @param \WP_Error|null|true $result Current authentication result.
	 * @return \WP_Error|null|true Modified result.
	 */
	public function require_rest_authentication( $result ) {
		// Pass through if a previous filter already set an error or success.
		if ( null !== $result ) {
			return $result;
		}

		if ( ! is_user_logged_in() ) {
			return new WP_Error(
				'sentinel_rest_forbidden',
				__( 'REST API access requires authentication.', 'wp-sentinel-security' ),
				array( 'status' => 401 )
			);
		}

		return $result;
	}

	// =========================================================================
	// 3. Disable oEmbed discovery
	// =========================================================================

	/**
	 * Apply: disable oEmbed discovery links and endpoint.
	 *
	 * @return array{status: string, message: string}
	 */
	public function disable_oembed() {
		update_option( 'sentinel_hardening_disable_oembed', true );
		return array(
			'status'  => 'applied',
			'message' => __( 'oEmbed discovery links and endpoint have been disabled.', 'wp-sentinel-security' ),
		);
	}

	/**
	 * Revert: re-enable oEmbed.
	 *
	 * @return array{status: string, message: string}
	 */
	public function revert_disable_oembed() {
		delete_option( 'sentinel_hardening_disable_oembed' );
		return array(
			'status'  => 'reverted',
			'message' => __( 'oEmbed has been re-enabled (WordPress default).', 'wp-sentinel-security' ),
		);
	}

	/**
	 * Status: check whether oEmbed is disabled.
	 *
	 * @return array{status: string, details: string}
	 */
	public function status_disable_oembed() {
		if ( get_option( 'sentinel_hardening_disable_oembed' ) ) {
			return array(
				'status'  => 'applied',
				'details' => __( 'oEmbed discovery links and endpoint are disabled.', 'wp-sentinel-security' ),
			);
		}
		return array(
			'status'  => 'not_applied',
			'details' => __( 'oEmbed is enabled (WordPress default).', 'wp-sentinel-security' ),
		);
	}

	/**
	 * Filter callback: strip oEmbed rewrite rules from the rewrite rules array.
	 *
	 * Hooked to 'rewrite_rules_array' when oEmbed is disabled.
	 *
	 * @param array $rules Existing rewrite rules.
	 * @return array Filtered rules without oEmbed entries.
	 */
	public function remove_oembed_rewrite_rules( array $rules ) {
		foreach ( $rules as $regex => $query ) {
			if ( false !== strpos( $query, 'oembed' ) ) {
				unset( $rules[ $regex ] );
			}
		}
		return $rules;
	}

	// =========================================================================
	// 4. Disable pingbacks
	// =========================================================================

	/**
	 * Apply: disable pingbacks and trackbacks site-wide.
	 *
	 * @return array{status: string, message: string}
	 */
	public function disable_pingbacks() {
		update_option( 'sentinel_hardening_disable_pingbacks', true );
		// Also update the WordPress setting so new posts default to pings off.
		update_option( 'default_ping_status', 'closed' );
		return array(
			'status'  => 'applied',
			'message' => __( 'Pingbacks and trackbacks have been disabled.', 'wp-sentinel-security' ),
		);
	}

	/**
	 * Revert: restore pingback / trackback functionality.
	 *
	 * @return array{status: string, message: string}
	 */
	public function revert_disable_pingbacks() {
		delete_option( 'sentinel_hardening_disable_pingbacks' );
		update_option( 'default_ping_status', 'open' );
		return array(
			'status'  => 'reverted',
			'message' => __( 'Pingbacks and trackbacks have been re-enabled.', 'wp-sentinel-security' ),
		);
	}

	/**
	 * Status: check whether pingbacks are disabled.
	 *
	 * @return array{status: string, details: string}
	 */
	public function status_disable_pingbacks() {
		$sentinel_option = get_option( 'sentinel_hardening_disable_pingbacks' );
		$wp_option       = get_option( 'default_ping_status' );

		if ( $sentinel_option && 'closed' === $wp_option ) {
			return array(
				'status'  => 'applied',
				'details' => __( 'Pingbacks and trackbacks are disabled site-wide.', 'wp-sentinel-security' ),
			);
		}

		if ( $sentinel_option || 'closed' === $wp_option ) {
			return array(
				'status'  => 'partial',
				'details' => __( 'Pingbacks are partially disabled. Sentinel option and WP default_ping_status are out of sync.', 'wp-sentinel-security' ),
			);
		}

		return array(
			'status'  => 'not_applied',
			'details' => __( 'Pingbacks and trackbacks are enabled (WordPress default).', 'wp-sentinel-security' ),
		);
	}

	/**
	 * Filter callback: remove the pingback.ping method from the XML-RPC method list.
	 *
	 * Hooked to 'xmlrpc_methods'.
	 *
	 * @param array $methods Available XML-RPC methods.
	 * @return array Methods with pingback.ping and pingback.extensions.getPingbacks removed.
	 */
	public function remove_pingback_method( array $methods ) {
		unset( $methods['pingback.ping'], $methods['pingback.extensions.getPingbacks'] );
		return $methods;
	}

	/**
	 * Action callback: prevent self-pings on the current site.
	 *
	 * Hooked to 'pre_ping'. WordPress calls this hook via do_action_ref_array(),
	 * so the $links parameter is intentionally passed by reference to allow
	 * in-place modification of the pending-pings list.
	 *
	 * @link https://developer.wordpress.org/reference/hooks/pre_ping/
	 *
	 * @param string[] $links Array of links that WordPress is about to ping (passed by reference).
	 * @return void
	 */
	public function disable_self_ping( &$links ) {
		$home = get_option( 'home' );
		foreach ( $links as $key => $link ) {
			if ( 0 === strpos( $link, $home ) ) {
				unset( $links[ $key ] );
			}
		}
	}

	/**
	 * Filter callback: remove the X-Pingback HTTP header from responses.
	 *
	 * Hooked to 'wp_headers'.
	 *
	 * @param array $headers Response headers array.
	 * @return array Headers without X-Pingback.
	 */
	public function remove_x_pingback_header( array $headers ) {
		unset( $headers['X-Pingback'] );
		return $headers;
	}

	// =========================================================================
	// Private helpers
	// =========================================================================

	/**
	 * Write a block of .htaccess rules wrapped in Sentinel marker comments.
	 *
	 * @param string[] $rules  Array of rule lines.
	 * @param string   $marker Unique marker label for the block.
	 * @return bool True on success, false on write failure.
	 */
	private function write_htaccess_marker( array $rules, $marker ) {
		$existing = '';
		if ( file_exists( $this->htaccess_path ) ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
			$existing = file_get_contents( $this->htaccess_path );
			if ( false === $existing ) {
				return false;
			}
		}

		// Remove any existing block for this marker before re-inserting.
		$pattern  = '/# BEGIN ' . preg_quote( $marker, '/' ) . '.*?# END ' . preg_quote( $marker, '/' ) . '\n?/s';
		$existing = preg_replace( $pattern, '', $existing );
		$existing = ltrim( $existing );

		$block  = '# BEGIN ' . $marker . "\n";
		$block .= implode( "\n", $rules ) . "\n";
		$block .= '# END ' . $marker . "\n\n";

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		return false !== file_put_contents( $this->htaccess_path, $block . $existing );
	}

	/**
	 * Remove a Sentinel marker block from the root .htaccess file.
	 *
	 * @param string $marker Marker label to remove.
	 * @return bool True on success (or if already absent), false on write failure.
	 */
	private function remove_htaccess_marker( $marker ) {
		if ( ! file_exists( $this->htaccess_path ) ) {
			return true;
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$contents = file_get_contents( $this->htaccess_path );
		if ( false === $contents ) {
			return false;
		}

		$pattern      = '/# BEGIN ' . preg_quote( $marker, '/' ) . '.*?# END ' . preg_quote( $marker, '/' ) . '\n?/s';
		$new_contents = preg_replace( $pattern, '', $contents );

		if ( $new_contents === $contents ) {
			return true;
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		return false !== file_put_contents( $this->htaccess_path, $new_contents );
	}

	/**
	 * Check whether a Sentinel marker block is present in the root .htaccess.
	 *
	 * @param string $marker Marker label to search for.
	 * @return bool True if the marker block exists.
	 */
	private function htaccess_has_marker( $marker ) {
		if ( ! file_exists( $this->htaccess_path ) ) {
			return false;
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$contents = file_get_contents( $this->htaccess_path );
		return false !== strpos( $contents, '# BEGIN ' . $marker );
	}
}
