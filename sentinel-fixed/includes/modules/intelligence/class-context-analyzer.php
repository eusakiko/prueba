<?php
/**
 * Context Analyzer — Contextual vulnerability analysis.
 *
 * @package WP_Sentinel_Security
 * @since   1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Context_Analyzer
 */
class Context_Analyzer {

	/**
	 * Analyze a vulnerability in context of the current environment.
	 *
	 * @param array $vulnerability Vulnerability data array with keys: component, type, description, severity.
	 * @param array $intelligence  Full intelligence data (environment fingerprint, attack surface, etc.).
	 * @return array Context array with risk factors.
	 */
	public function analyze_vulnerability( $vulnerability, $intelligence ) {
		$component   = $vulnerability['component'] ?? '';
		$type        = $vulnerability['type'] ?? '';
		$description = $vulnerability['description'] ?? '';

		$is_active         = $this->is_component_active( $component, $type );
		$is_used           = $this->is_functionality_used( $component, $type );
		$is_exposed        = $this->is_publicly_exposed( $component, $type, $intelligence );
		$requires_auth     = $this->requires_authentication( $description );
		$has_exploit       = $this->has_known_exploit( $vulnerability );
		$behind_waf        = $this->is_behind_waf( $intelligence );

		$mitigating  = array();
		$aggravating = array();
		$multiplier  = 1.0;

		// Component not active — drastically reduces risk.
		if ( ! $is_active ) {
			$multiplier  *= 0.2;
			$mitigating[] = __( 'Component is inactive', 'wp-sentinel-security' );
		}

		// Not publicly exposed — reduces risk.
		if ( ! $is_exposed ) {
			$multiplier  *= 0.6;
			$mitigating[] = __( 'Not publicly exposed', 'wp-sentinel-security' );
		}

		// Known exploit raises risk.
		if ( $has_exploit ) {
			$multiplier     *= 2.0;
			$aggravating[]   = __( 'Known public exploit exists', 'wp-sentinel-security' );
		}

		// WAF reduces effective risk.
		if ( $behind_waf ) {
			$multiplier  *= 0.8;
			$mitigating[] = __( 'Protected by WAF', 'wp-sentinel-security' );
		}

		// Authentication required mitigates unauthenticated exposure.
		if ( $requires_auth ) {
			$mitigating[] = __( 'Requires authentication', 'wp-sentinel-security' );
		} else {
			$aggravating[] = __( 'Exploitable without authentication', 'wp-sentinel-security' );
		}

		return array(
			'is_component_active'    => $is_active,
			'is_functionality_used'  => $is_used,
			'is_publicly_exposed'    => $is_exposed,
			'requires_authentication' => $requires_auth,
			'has_known_exploit'      => $has_exploit,
			'is_behind_waf'          => $behind_waf,
			'risk_multiplier'        => round( $multiplier, 4 ),
			'mitigating_factors'     => $mitigating,
			'aggravating_factors'    => $aggravating,
		);
	}

	/**
	 * Check whether the affected component is active.
	 *
	 * @param string $component Component slug / name.
	 * @param string $type      Vulnerability type (plugin|theme|core|config|...).
	 * @return bool
	 */
	private function is_component_active( $component, $type ) {
		if ( 'plugin' === $type ) {
			if ( ! function_exists( 'is_plugin_active' ) ) {
				require_once ABSPATH . 'wp-admin/includes/plugin.php';
			}
			// Component may be "plugin-folder/plugin-file.php" or just the folder.
			if ( is_plugin_active( $component ) ) {
				return true;
			}
			// Try matching against all active plugins by slug prefix.
			$active = get_option( 'active_plugins', array() );
			foreach ( $active as $plugin_file ) {
				if ( 0 === strpos( $plugin_file, trailingslashit( $component ) ) || $plugin_file === $component ) {
					return true;
				}
			}
			return false;
		}

		if ( 'theme' === $type ) {
			$current_theme = wp_get_theme();
			return (
				$current_theme->get_stylesheet() === $component ||
				$current_theme->get_template() === $component
			);
		}

		// Core and config vulnerabilities are always "active".
		return true;
	}

	/**
	 * Check whether the vulnerable functionality is used on the site.
	 *
	 * @param string $component Component slug.
	 * @param string $type      Vulnerability type.
	 * @return bool
	 */
	private function is_functionality_used( $component, $type ) {
		if ( ! in_array( $type, array( 'plugin', 'theme' ), true ) ) {
			return true;
		}

		global $wpdb;

		// Check options for stored component data.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$option_exists = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name LIKE %s LIMIT 1",
				'%' . $wpdb->esc_like( $component ) . '%'
			)
		);

		if ( $option_exists ) {
			return true;
		}

		// Check posts/content for shortcodes from the component.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$shortcode_used = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_content LIKE %s AND post_status = %s LIMIT 1",
				'%[' . $wpdb->esc_like( $component ) . '%',
				'publish'
			)
		);

		return (bool) $shortcode_used;
	}

	/**
	 * Check whether the component has public-facing exposure.
	 *
	 * @param string $component   Component slug.
	 * @param string $type        Vulnerability type.
	 * @param array  $intelligence Intelligence data including attack surface.
	 * @return bool
	 */
	private function is_publicly_exposed( $component, $type, $intelligence ) {
		// Check REST endpoints registered by this component.
		if ( ! empty( $intelligence['attack_surface']['rest_endpoints'] ) ) {
			foreach ( $intelligence['attack_surface']['rest_endpoints'] as $endpoint ) {
				$ns = $endpoint['namespace'] ?? '';
				if ( false !== stripos( $ns, $component ) ) {
					return true;
				}
			}
		}

		// Check nopriv AJAX actions.
		if ( ! empty( $intelligence['attack_surface']['ajax_actions'] ) ) {
			foreach ( $intelligence['attack_surface']['ajax_actions'] as $action ) {
				if ( false !== stripos( $action, $component ) ) {
					return true;
				}
			}
		}

		// Plugins / themes that are active and not explicitly admin-only are assumed exposed.
		if ( in_array( $type, array( 'plugin', 'theme', 'core' ), true ) ) {
			return true;
		}

		return false;
	}

	/**
	 * Parse vulnerability description to determine if authentication is required.
	 *
	 * @param string $description Vulnerability description text.
	 * @return bool True if authentication IS required (i.e. not unauthenticated).
	 */
	private function requires_authentication( $description ) {
		$unauthenticated_patterns = array(
			'unauthenticated',
			'no authentication',
			'without authentication',
			'unauthorized',
			'remote attacker',
			'any visitor',
		);

		$lower = strtolower( $description );
		foreach ( $unauthenticated_patterns as $pattern ) {
			if ( false !== strpos( $lower, $pattern ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Check whether a known public exploit exists for the vulnerability.
	 * Results are cached for 24 hours.
	 *
	 * @param array $vulnerability Vulnerability data.
	 * @return bool
	 */
	private function has_known_exploit( $vulnerability ) {
		$cve = $vulnerability['cve_id'] ?? '';

		if ( ! $cve ) {
			return false;
		}

		$cache_key = 'sentinel_exploit_' . md5( $cve );
		$cached    = get_transient( $cache_key );

		if ( false !== $cached ) {
			return (bool) $cached;
		}

		// Query GitHub Advisories API.
		$url      = 'https://api.github.com/advisories?cve_id=' . rawurlencode( $cve ) . '&per_page=1';
		$response = wp_remote_get(
			$url,
			array(
				'timeout' => 10,
				'headers' => array(
					'Accept'     => 'application/vnd.github+json',
					'User-Agent' => 'WP-Sentinel-Security/' . SENTINEL_VERSION,
				),
			)
		);

		$has_exploit = false;

		if ( ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ) {
			$body = json_decode( wp_remote_retrieve_body( $response ), true );
			if ( ! empty( $body ) && is_array( $body ) && count( $body ) > 0 ) {
				foreach ( $body as $advisory ) {
					if ( ! empty( $advisory['vulnerabilities'] ) ) {
						$has_exploit = true;
						break;
					}
				}
			}
		}

		set_transient( $cache_key, $has_exploit ? 1 : 0, DAY_IN_SECONDS );

		return $has_exploit;
	}

	/**
	 * Determine whether the site is behind a WAF based on environment data.
	 *
	 * @param array $intelligence Intelligence data.
	 * @return bool
	 */
	private function is_behind_waf( $intelligence ) {
		$hosting = $intelligence['environment']['hosting'] ?? array();

		if ( ! empty( $hosting['waf'] ) ) {
			foreach ( $hosting['waf'] as $waf => $active ) {
				if ( $active ) {
					return true;
				}
			}
		}

		return false;
	}
}
