<?php
/**
 * Attack Surface Mapper — Maps the entire public attack surface of the site.
 *
 * @package WP_Sentinel_Security
 * @since   1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Attack_Surface_Mapper
 */
class Attack_Surface_Mapper {

	/**
	 * Build a complete attack-surface map.
	 *
	 * @return array Map with rest_endpoints, ajax_actions, public_files, login_endpoints,
	 *               xmlrpc, user_enumeration, feeds, rewrite_rules.
	 */
	public function map() {
		return array(
			'rest_endpoints'    => $this->get_rest_endpoints(),
			'ajax_actions'      => $this->get_nopriv_ajax_actions(),
			'public_files'      => $this->get_public_files(),
			'login_endpoints'   => $this->get_login_endpoints(),
			'xmlrpc'            => $this->get_xmlrpc_info(),
			'user_enumeration'  => $this->get_user_enumeration_info(),
			'feeds'             => $this->get_feeds(),
			'rewrite_rules'     => $this->get_rewrite_rules(),
		);
	}

	/**
	 * List registered REST API endpoints with their auth requirements.
	 *
	 * @return array
	 */
	private function get_rest_endpoints() {
		$server = rest_get_server();
		$routes = $server->get_routes();

		$endpoints = array();
		foreach ( $routes as $route => $handlers ) {
			$methods          = array();
			$requires_auth    = false;

			foreach ( $handlers as $handler ) {
				if ( ! empty( $handler['methods'] ) ) {
					$methods = array_merge( $methods, array_keys( (array) $handler['methods'] ) );
				}
				if ( ! empty( $handler['permission_callback'] ) && '__return_true' !== $handler['permission_callback'] ) {
					$requires_auth = true;
				}
			}

			// Derive namespace from route.
			$namespace = '';
			if ( preg_match( '#^/([^/]+/v\d+)#', $route, $matches ) ) {
				$namespace = $matches[1];
			}

			$endpoints[] = array(
				'route'          => $route,
				'namespace'      => $namespace,
				'methods'        => array_unique( $methods ),
				'requires_auth'  => $requires_auth,
			);
		}

		return $endpoints;
	}

	/**
	 * Discover nopriv (unauthenticated) AJAX actions from the $wp_filter global.
	 *
	 * @return array List of action names.
	 */
	private function get_nopriv_ajax_actions() {
		global $wp_filter;

		$actions = array();
		$prefix  = 'wp_ajax_nopriv_';

		foreach ( array_keys( $wp_filter ) as $hook ) {
			if ( 0 === strpos( $hook, $prefix ) ) {
				$actions[] = substr( $hook, strlen( $prefix ) );
			}
		}

		return $actions;
	}

	/**
	 * Check whether common sensitive files are publicly accessible.
	 *
	 * @return array Map of file path => array(accessible, url).
	 */
	private function get_public_files() {
		$files = array(
			'readme.html'    => site_url( '/readme.html' ),
			'license.txt'    => site_url( '/license.txt' ),
			'xmlrpc.php'     => site_url( '/xmlrpc.php' ),
			'wp-config.php'  => site_url( '/wp-config.php' ),
			'debug.log'      => content_url( '/debug.log' ),
			'.htaccess'      => site_url( '/.htaccess' ),
			'wp-login.php'   => site_url( '/wp-login.php' ),
		);

		$result = array();
		foreach ( $files as $label => $url ) {
			// sslverify intentionally false: scanning the site's own URLs which may use
			// self-signed or locally-terminated TLS certificates.
			$response   = wp_remote_head( $url, array( 'timeout' => 8, 'sslverify' => false ) );
			$code       = is_wp_error( $response ) ? 0 : wp_remote_retrieve_response_code( $response );
			$accessible = in_array( (int) $code, array( 200, 301, 302 ), true );

			$result[ $label ] = array(
				'url'        => $url,
				'accessible' => $accessible,
				'http_code'  => $code,
			);
		}

		return $result;
	}

	/**
	 * Determine login endpoint URLs and registration status.
	 *
	 * @return array
	 */
	private function get_login_endpoints() {
		return array(
			'login_url'          => wp_login_url(),
			'registration_open'  => (bool) get_option( 'users_can_register' ),
			'lost_password_url'  => wp_lostpassword_url(),
		);
	}

	/**
	 * Test whether XML-RPC is enabled.
	 *
	 * @return array
	 */
	private function get_xmlrpc_info() {
		$xmlrpc_url = site_url( '/xmlrpc.php' );

		// sslverify intentionally false: scanning the site's own endpoint which may use
		// self-signed or locally-terminated TLS certificates.
		$response = wp_remote_post(
			$xmlrpc_url,
			array(
				'timeout'   => 8,
				'body'      => '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>',
				'headers'   => array( 'Content-Type' => 'text/xml' ),
				'sslverify' => false,
			)
		);

		$enabled = false;
		$methods = array();

		if ( ! is_wp_error( $response ) ) {
			$code = wp_remote_retrieve_response_code( $response );
			$body = wp_remote_retrieve_body( $response );

			if ( 200 === (int) $code && false !== strpos( $body, '<methodResponse>' ) ) {
				$enabled = true;
				// Extract method names simply.
				preg_match_all( '#<value><string>([^<]+)</string></value>#', $body, $m );
				$methods = $m[1] ?? array();
			}
		}

		return array(
			'enabled' => $enabled,
			'url'     => $xmlrpc_url,
			'methods' => $methods,
		);
	}

	/**
	 * Test user enumeration vectors.
	 *
	 * @return array
	 */
	private function get_user_enumeration_info() {
		$result = array(
			'rest_users_exposed'   => false,
			'author_enum_exposed'  => false,
		);

		// Check REST /wp/v2/users — sslverify false for same-site self-checks.
		$rest_url = rest_url( 'wp/v2/users' );
		$response = wp_remote_get( $rest_url, array( 'timeout' => 8, 'sslverify' => false ) );

		if ( ! is_wp_error( $response ) && 200 === (int) wp_remote_retrieve_response_code( $response ) ) {
			$data = json_decode( wp_remote_retrieve_body( $response ), true );
			if ( ! empty( $data ) && is_array( $data ) ) {
				$result['rest_users_exposed'] = true;
			}
		}

		// Check author enumeration via ?author=1 redirect.
		$author_url = add_query_arg( 'author', '1', home_url( '/' ) );
		$response   = wp_remote_get(
			$author_url,
			array(
				'timeout'     => 8,
				'sslverify'   => false,
				'redirection' => 0,
			)
		);

		if ( ! is_wp_error( $response ) ) {
			$code     = (int) wp_remote_retrieve_response_code( $response );
			$location = wp_remote_retrieve_header( $response, 'location' );

			if ( in_array( $code, array( 301, 302 ), true ) && false !== strpos( (string) $location, '/author/' ) ) {
				$result['author_enum_exposed'] = true;
			}
		}

		return $result;
	}

	/**
	 * Check whether common feeds are enabled.
	 *
	 * @return array
	 */
	private function get_feeds() {
		return array(
			'rss2' => get_feed_link( 'rss2' ),
			'atom' => get_feed_link( 'atom' ),
			'rss'  => get_feed_link( 'rss' ),
		);
	}

	/**
	 * Return first 50 registered rewrite rules.
	 *
	 * @return array
	 */
	private function get_rewrite_rules() {
		global $wp_rewrite;

		if ( $wp_rewrite ) {
			$rules = (array) $wp_rewrite->rules;
		} else {
			$rules = (array) get_option( 'rewrite_rules', array() );
		}

		return array_slice( $rules, 0, 50, true );
	}
}
