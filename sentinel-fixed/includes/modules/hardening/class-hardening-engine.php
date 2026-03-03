<?php
/**
 * Hardening Engine — Orchestrates all hardening sub-classes.
 *
 * Provides a unified interface for:
 *   - Listing all available hardening checks (with current status)
 *   - Applying / reverting individual checks
 *   - Calculating an overall hardening score
 *   - Handling AJAX requests from the admin UI
 *
 * @package WP_Sentinel_Security
 * @since   2.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Hardening_Engine
 */
class Hardening_Engine {

	/**
	 * Plugin settings.
	 *
	 * @var array
	 */
	private $settings;

	/**
	 * Loaded sub-class instances, keyed by short name.
	 *
	 * @var array{
	 *   file:     File_Hardening,
	 *   wp_config: WP_Config_Hardening,
	 *   user:     User_Hardening,
	 *   database: Database_Hardening,
	 *   api:      API_Hardening,
	 * }
	 */
	private $handlers = array();

	/**
	 * Master check registry.
	 *
	 * Each entry defines a single hardening check and maps it to a handler class
	 * plus a method-base (apply / revert / status methods are derived from it).
	 *
	 * @var array[]
	 */
	private static $check_definitions = array(

		// ── File Security ───────────────────────────────────────────────────
		array(
			'id'          => 'disable_file_editing',
			'name'        => 'Disable File Editing',
			'category'    => 'file_security',
			'description' => 'Prevents administrators from editing plugin and theme files via the WordPress admin panel by defining DISALLOW_FILE_EDIT.',
			'risk_level'  => 'high',
			'handler'     => 'file',
		),
		array(
			'id'          => 'block_php_uploads',
			'name'        => 'Block PHP Execution in Uploads',
			'category'    => 'file_security',
			'description' => 'Adds an .htaccess rule to the uploads directory that prevents PHP files from being executed — mitigating malware-upload attacks.',
			'risk_level'  => 'critical',
			'handler'     => 'file',
		),
		array(
			'id'          => 'protect_wp_config',
			'name'        => 'Protect wp-config.php Permissions',
			'category'    => 'file_security',
			'description' => 'Sets wp-config.php file permissions to 0440 so it cannot be read by other system users.',
			'risk_level'  => 'high',
			'handler'     => 'file',
		),
		array(
			'id'          => 'protect_htaccess',
			'name'        => 'Protect .htaccess Permissions',
			'category'    => 'file_security',
			'description' => 'Sets the root .htaccess file to read-only (0444) to prevent unauthorised modification.',
			'risk_level'  => 'medium',
			'handler'     => 'file',
		),
		array(
			'id'          => 'disable_directory_listing',
			'name'        => 'Disable Directory Listing',
			'category'    => 'file_security',
			'description' => 'Adds "Options -Indexes" to .htaccess to prevent Apache from listing directory contents when no index file is present.',
			'risk_level'  => 'medium',
			'handler'     => 'file',
		),
		array(
			'id'          => 'add_security_headers',
			'name'        => 'HTTP Security Headers',
			'category'    => 'file_security',
			'description' => 'Injects security-hardening HTTP response headers (X-Content-Type-Options, X-Frame-Options, CSP, Referrer-Policy, etc.) via .htaccess.',
			'risk_level'  => 'medium',
			'handler'     => 'file',
		),

		// ── WP Config ───────────────────────────────────────────────────────
		array(
			'id'          => 'force_ssl_admin',
			'name'        => 'Force SSL for Admin',
			'category'    => 'wp_config',
			'description' => 'Defines FORCE_SSL_ADMIN in wp-config.php to enforce HTTPS for all WordPress admin sessions.',
			'risk_level'  => 'high',
			'handler'     => 'wp_config',
		),
		array(
			'id'          => 'disable_debug',
			'name'        => 'Disable Debug Mode',
			'category'    => 'wp_config',
			'description' => 'Sets WP_DEBUG to false in wp-config.php to prevent error messages from leaking server information to visitors.',
			'risk_level'  => 'medium',
			'handler'     => 'wp_config',
		),
		array(
			'id'          => 'limit_post_revisions',
			'name'        => 'Limit Post Revisions',
			'category'    => 'wp_config',
			'description' => 'Sets WP_POST_REVISIONS to 5 in wp-config.php to reduce database bloat and limit stored content history.',
			'risk_level'  => 'low',
			'handler'     => 'wp_config',
		),
		array(
			'id'          => 'set_autosave_interval',
			'name'        => 'Increase Autosave Interval',
			'category'    => 'wp_config',
			'description' => 'Sets AUTOSAVE_INTERVAL to 300 seconds (5 minutes) in wp-config.php to reduce unnecessary write operations.',
			'risk_level'  => 'low',
			'handler'     => 'wp_config',
		),
		array(
			'id'          => 'disable_file_editor',
			'name'        => 'Disable File Editor (wp-config)',
			'category'    => 'wp_config',
			'description' => 'Defines DISALLOW_FILE_EDIT in wp-config.php to disable the built-in theme and plugin code editor.',
			'risk_level'  => 'high',
			'handler'     => 'wp_config',
		),
		array(
			'id'          => 'disable_unfiltered_html',
			'name'        => 'Disable Unfiltered HTML',
			'category'    => 'wp_config',
			'description' => 'Defines DISALLOW_UNFILTERED_HTML to prevent non-admin users from inserting raw HTML that could contain malicious scripts.',
			'risk_level'  => 'high',
			'handler'     => 'wp_config',
		),
		array(
			'id'          => 'set_empty_trash_days',
			'name'        => 'Set Trash Retention Period',
			'category'    => 'wp_config',
			'description' => 'Sets EMPTY_TRASH_DAYS to 7 in wp-config.php so deleted content is purged within a week.',
			'risk_level'  => 'low',
			'handler'     => 'wp_config',
		),

		// ── User Security ───────────────────────────────────────────────────
		array(
			'id'          => 'disable_user_enumeration',
			'name'        => 'Block User Enumeration',
			'category'    => 'user_security',
			'description' => 'Adds an .htaccess RewriteRule to return HTTP 403 for requests that attempt to enumerate WordPress users via ?author=N.',
			'risk_level'  => 'medium',
			'handler'     => 'user',
		),
		array(
			'id'          => 'enforce_strong_passwords',
			'name'        => 'Enforce Strong Passwords',
			'category'    => 'user_security',
			'description' => 'Hooks into WordPress password validation to require a minimum of 12 characters with uppercase, lowercase, numbers, and symbols.',
			'risk_level'  => 'high',
			'handler'     => 'user',
		),
		array(
			'id'          => 'limit_login_attempts',
			'name'        => 'Limit Login Attempts',
			'category'    => 'user_security',
			'description' => 'Locks out an IP address for 15 minutes after 5 consecutive failed login attempts using WordPress transients.',
			'risk_level'  => 'high',
			'handler'     => 'user',
		),
		array(
			'id'          => 'disable_application_passwords',
			'name'        => 'Disable Application Passwords',
			'category'    => 'user_security',
			'description' => 'Removes the Application Passwords feature that allows REST API authentication — useful when REST API access should be restricted.',
			'risk_level'  => 'medium',
			'handler'     => 'user',
		),
		array(
			'id'          => 'hide_wp_version',
			'name'        => 'Hide WordPress Version',
			'category'    => 'user_security',
			'description' => 'Removes the WordPress generator meta tag and RSS generator tag that expose the running WordPress version to potential attackers.',
			'risk_level'  => 'low',
			'handler'     => 'user',
		),

		// ── Database Security ───────────────────────────────────────────────
		array(
			'id'          => 'check_table_prefix',
			'name'        => 'Custom Database Table Prefix',
			'category'    => 'database_security',
			'description' => 'Checks whether the default "wp_" table prefix is in use. Using a custom prefix reduces the risk from SQL-injection-based enumeration.',
			'risk_level'  => 'medium',
			'handler'     => 'database',
		),
		array(
			'id'          => 'check_db_privileges',
			'name'        => 'Database User Privileges',
			'category'    => 'database_security',
			'description' => 'Audits the database user\'s MySQL privileges to detect excessive permissions such as FILE, SUPER, or GRANT OPTION.',
			'risk_level'  => 'high',
			'handler'     => 'database',
		),
		array(
			'id'          => 'check_db_password_strength',
			'name'        => 'Database Password Strength',
			'category'    => 'database_security',
			'description' => 'Evaluates the DB_PASSWORD constant for minimum length (16 chars) and character-class diversity without storing or exposing it.',
			'risk_level'  => 'high',
			'handler'     => 'database',
		),

		// ── API Security ────────────────────────────────────────────────────
		array(
			'id'          => 'disable_xmlrpc',
			'name'        => 'Disable XML-RPC',
			'category'    => 'api_security',
			'description' => 'Disables the XML-RPC interface via WordPress filter and .htaccess to prevent brute-force and DDoS amplification attacks.',
			'risk_level'  => 'high',
			'handler'     => 'api',
		),
		array(
			'id'          => 'restrict_rest_api',
			'name'        => 'Restrict REST API Access',
			'category'    => 'api_security',
			'description' => 'Requires authentication for all REST API requests from non-logged-in users to prevent information disclosure.',
			'risk_level'  => 'medium',
			'handler'     => 'api',
		),
		array(
			'id'          => 'disable_oembed',
			'name'        => 'Disable oEmbed',
			'category'    => 'api_security',
			'description' => 'Removes oEmbed discovery links and disables the oEmbed REST endpoint to reduce information leakage and SSRF risk.',
			'risk_level'  => 'low',
			'handler'     => 'api',
		),
		array(
			'id'          => 'disable_pingbacks',
			'name'        => 'Disable Pingbacks',
			'category'    => 'api_security',
			'description' => 'Disables WordPress pingbacks and trackbacks to prevent DDoS amplification and unwanted inbound requests.',
			'risk_level'  => 'medium',
			'handler'     => 'api',
		),
	);

	/**
	 * Constructor.
	 *
	 * @param array $settings Plugin settings.
	 */
	public function __construct( $settings = array() ) {
		$this->settings = $settings;
	}

	/**
	 * Initialise the hardening engine: load sub-classes and register AJAX handlers.
	 *
	 * @return void
	 */
	public function init() {
		$dir = SENTINEL_PLUGIN_DIR . 'includes/modules/hardening/';

		require_once $dir . 'class-file-hardening.php';
		require_once $dir . 'class-wp-config-hardening.php';
		require_once $dir . 'class-user-hardening.php';
		require_once $dir . 'class-database-hardening.php';
		require_once $dir . 'class-api-hardening.php';

		$this->handlers['file']      = new File_Hardening();
		$this->handlers['wp_config'] = new WP_Config_Hardening();
		$this->handlers['user']      = new User_Hardening();
		$this->handlers['database']  = new Database_Hardening();
		$this->handlers['api']       = new API_Hardening();

		// AJAX handlers — authenticated admins only.
		add_action( 'wp_ajax_sentinel_apply_hardening',      array( $this, 'ajax_apply_hardening' ) );
		add_action( 'wp_ajax_sentinel_revert_hardening',     array( $this, 'ajax_revert_hardening' ) );
		add_action( 'wp_ajax_sentinel_get_hardening_status', array( $this, 'ajax_get_hardening_status' ) );
	}

	// =========================================================================
	// Public API
	// =========================================================================

	/**
	 * Return all hardening checks, each enriched with the current live status.
	 *
	 * @return array[] Array of check arrays with keys:
	 *   id, name, category, description, risk_level, status, details.
	 */
	public function get_all_checks() {
		$checks = array();

		foreach ( self::$check_definitions as $def ) {
			$status_data = $this->get_check_status( $def['id'] );

			$checks[] = array(
				'id'          => $def['id'],
				'name'        => $def['name'],
				'category'    => $def['category'],
				'description' => $def['description'],
				'risk_level'  => $def['risk_level'],
				'status'      => $status_data['status'],
				'details'     => $status_data['details'],
			);
		}

		return $checks;
	}

	/**
	 * Get the current status of a single check.
	 *
	 * @param string $check_id Check identifier.
	 * @return array{status: string, details: string}
	 */
	public function get_check_status( $check_id ) {
		$def = $this->find_definition( $check_id );
		if ( ! $def ) {
			return array(
				'status'  => 'unknown',
				'details' => __( 'Check not found.', 'wp-sentinel-security' ),
			);
		}

		$handler = $this->handlers[ $def['handler'] ] ?? null;
		if ( ! $handler ) {
			return array(
				'status'  => 'error',
				'details' => __( 'Handler not loaded.', 'wp-sentinel-security' ),
			);
		}

		$method = 'status_' . $check_id;
		if ( method_exists( $handler, $method ) ) {
			return $handler->$method();
		}

		return array(
			'status'  => 'error',
			'details' => __( 'Status method not found.', 'wp-sentinel-security' ),
		);
	}

	/**
	 * Apply a hardening check by ID.
	 *
	 * @param string $check_id Check identifier.
	 * @return array{status: string, message: string}
	 */
	public function apply_check( $check_id ) {
		$def = $this->find_definition( $check_id );
		if ( ! $def ) {
			return array(
				'status'  => 'error',
				'message' => __( 'Unknown check ID.', 'wp-sentinel-security' ),
			);
		}

		$handler = $this->handlers[ $def['handler'] ] ?? null;
		if ( ! $handler ) {
			return array(
				'status'  => 'error',
				'message' => __( 'Handler not loaded.', 'wp-sentinel-security' ),
			);
		}

		$method = $check_id; // apply method name equals check_id for all sub-classes.
		if ( method_exists( $handler, $method ) ) {
			return $handler->$method();
		}

		return array(
			'status'  => 'error',
			'message' => __( 'Apply method not found.', 'wp-sentinel-security' ),
		);
	}

	/**
	 * Revert a hardening check by ID.
	 *
	 * @param string $check_id Check identifier.
	 * @return array{status: string, message: string}
	 */
	public function revert_check( $check_id ) {
		$def = $this->find_definition( $check_id );
		if ( ! $def ) {
			return array(
				'status'  => 'error',
				'message' => __( 'Unknown check ID.', 'wp-sentinel-security' ),
			);
		}

		$handler = $this->handlers[ $def['handler'] ] ?? null;
		if ( ! $handler ) {
			return array(
				'status'  => 'error',
				'message' => __( 'Handler not loaded.', 'wp-sentinel-security' ),
			);
		}

		$method = 'revert_' . $check_id;
		if ( method_exists( $handler, $method ) ) {
			return $handler->$method();
		}

		return array(
			'status'  => 'error',
			'message' => __( 'Revert method not found.', 'wp-sentinel-security' ),
		);
	}

	/**
	 * Calculate the overall hardening score as a percentage.
	 *
	 * Only checks with status 'applied' count toward the score.
	 * Checks with status 'partial' count as half a point.
	 *
	 * @return int Score from 0 to 100.
	 */
	public function get_hardening_score() {
		$checks = $this->get_all_checks();
		$total  = count( $checks );

		if ( 0 === $total ) {
			return 0;
		}

		$points = 0.0;
		foreach ( $checks as $check ) {
			if ( 'applied' === $check['status'] ) {
				$points += 1.0;
			} elseif ( 'partial' === $check['status'] ) {
				$points += 0.5;
			}
		}

		return (int) round( ( $points / $total ) * 100 );
	}

	/**
	 * Return all unique check categories.
	 *
	 * @return string[] Category slugs sorted alphabetically.
	 */
	public function get_categories() {
		$categories = array_unique(
			array_column( self::$check_definitions, 'category' )
		);
		sort( $categories );
		return $categories;
	}

	// =========================================================================
	// AJAX handlers
	// =========================================================================

	/**
	 * AJAX: apply a single hardening check.
	 *
	 * Expected POST params: nonce, check_id.
	 *
	 * @return void
	 */
	public function ajax_apply_hardening() {
		check_ajax_referer( 'sentinel_hardening_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error(
				array( 'message' => __( 'Insufficient permissions.', 'wp-sentinel-security' ) ),
				403
			);
		}

		$check_id = isset( $_POST['check_id'] ) ? sanitize_key( wp_unslash( $_POST['check_id'] ) ) : '';

		if ( empty( $check_id ) ) {
			wp_send_json_error( array( 'message' => __( 'Missing check_id parameter.', 'wp-sentinel-security' ) ) );
		}

		$result = $this->apply_check( $check_id );
		$status = $this->get_check_status( $check_id );

		wp_send_json_success(
			array(
				'result'       => $result,
				'check_status' => $status,
				'score'        => $this->get_hardening_score(),
			)
		);
	}

	/**
	 * AJAX: revert a single hardening check.
	 *
	 * Expected POST params: nonce, check_id.
	 *
	 * @return void
	 */
	public function ajax_revert_hardening() {
		check_ajax_referer( 'sentinel_hardening_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error(
				array( 'message' => __( 'Insufficient permissions.', 'wp-sentinel-security' ) ),
				403
			);
		}

		$check_id = isset( $_POST['check_id'] ) ? sanitize_key( wp_unslash( $_POST['check_id'] ) ) : '';

		if ( empty( $check_id ) ) {
			wp_send_json_error( array( 'message' => __( 'Missing check_id parameter.', 'wp-sentinel-security' ) ) );
		}

		$result = $this->revert_check( $check_id );
		$status = $this->get_check_status( $check_id );

		wp_send_json_success(
			array(
				'result'       => $result,
				'check_status' => $status,
				'score'        => $this->get_hardening_score(),
			)
		);
	}

	/**
	 * AJAX: return the current status of all checks plus the overall score.
	 *
	 * Expected POST params: nonce.
	 * Optional POST param:  check_id (returns status for a single check if provided).
	 *
	 * @return void
	 */
	public function ajax_get_hardening_status() {
		check_ajax_referer( 'sentinel_hardening_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error(
				array( 'message' => __( 'Insufficient permissions.', 'wp-sentinel-security' ) ),
				403
			);
		}

		$check_id = isset( $_POST['check_id'] ) ? sanitize_key( wp_unslash( $_POST['check_id'] ) ) : '';

		if ( $check_id ) {
			wp_send_json_success(
				array(
					'check_status' => $this->get_check_status( $check_id ),
					'score'        => $this->get_hardening_score(),
				)
			);
		}

		wp_send_json_success(
			array(
				'checks' => $this->get_all_checks(),
				'score'  => $this->get_hardening_score(),
			)
		);
	}

	// =========================================================================
	// Private helpers
	// =========================================================================

	/**
	 * Find a check definition by ID.
	 *
	 * @param string $check_id Check identifier.
	 * @return array|null Definition array or null if not found.
	 */
	private function find_definition( $check_id ) {
		foreach ( self::$check_definitions as $def ) {
			if ( $def['id'] === $check_id ) {
				return $def;
			}
		}
		return null;
	}
}
