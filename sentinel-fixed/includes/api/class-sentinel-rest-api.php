<?php
/**
 * REST API endpoints for WP Sentinel Security.
 *
 * @package WP_Sentinel_Security
 * @since   1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Sentinel_Rest_Api
 */
class Sentinel_Rest_Api {

	/**
	 * API namespace.
	 *
	 * @var string
	 */
	const API_NAMESPACE = 'sentinel/v1';

	/**
	 * Register REST API routes.
	 *
	 * @return void
	 */
	public static function register_routes() {
		$permission = array( __CLASS__, 'check_permission' );

		register_rest_route(
			self::API_NAMESPACE,
			'/status',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => array( __CLASS__, 'get_status' ),
				'permission_callback' => $permission,
			)
		);

		register_rest_route(
			self::API_NAMESPACE,
			'/scans',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => array( __CLASS__, 'get_scans' ),
				'permission_callback' => $permission,
				'args'                => array(
					'page'     => array( 'type' => 'integer', 'default' => 1, 'minimum' => 1 ),
					'per_page' => array( 'type' => 'integer', 'default' => 20, 'minimum' => 1, 'maximum' => 100 ),
				),
			)
		);

		register_rest_route(
			self::API_NAMESPACE,
			'/scan',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( __CLASS__, 'start_scan' ),
				'permission_callback' => $permission,
				'args'                => array(
					'scan_type' => array(
						'type'              => 'string',
						'default'           => 'quick',
						'enum'              => array( 'quick', 'full', 'malware', 'integrity' ),
						'sanitize_callback' => 'sanitize_key',
					),
				),
			)
		);

		register_rest_route(
			self::API_NAMESPACE,
			'/vulnerabilities',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => array( __CLASS__, 'get_vulnerabilities' ),
				'permission_callback' => $permission,
				'args'                => array(
					'severity'       => array(
						'type'              => 'string',
						'enum'              => array( 'critical', 'high', 'medium', 'low', 'info' ),
						'sanitize_callback' => 'sanitize_key',
					),
					'component_type' => array(
						'type'              => 'string',
						'enum'              => array( 'plugin', 'theme', 'wordpress', 'other' ),
						'sanitize_callback' => 'sanitize_key',
					),
					'status'         => array(
						'type'              => 'string',
						'enum'              => array( 'open', 'fixed', 'ignored', 'false_positive' ),
						'sanitize_callback' => 'sanitize_key',
					),
				),
			)
		);

		register_rest_route(
			self::API_NAMESPACE,
			'/vulnerabilities/(?P<id>\d+)',
			array(
				'methods'             => WP_REST_Server::EDITABLE,
				'callback'            => array( __CLASS__, 'update_vulnerability' ),
				'permission_callback' => $permission,
				'args'                => array(
					'id'     => array( 'type' => 'integer', 'required' => true ),
					'status' => array(
						'type'    => 'string',
						'enum'    => array( 'open', 'fixed', 'ignored', 'false_positive' ),
						'required' => true,
					),
				),
			)
		);

		// Hardening routes.
		register_rest_route(
			self::API_NAMESPACE,
			'/hardening',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => array( __CLASS__, 'get_hardening' ),
				'permission_callback' => $permission,
			)
		);

		register_rest_route(
			self::API_NAMESPACE,
			'/hardening/(?P<rule_id>[a-z0-9_]+)/apply',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( __CLASS__, 'apply_hardening_rule' ),
				'permission_callback' => $permission,
				'args'                => array(
					'rule_id' => array( 'type' => 'string', 'required' => true ),
				),
			)
		);

		register_rest_route(
			self::API_NAMESPACE,
			'/hardening/(?P<rule_id>[a-z0-9_]+)/revert',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( __CLASS__, 'revert_hardening_rule' ),
				'permission_callback' => $permission,
				'args'                => array(
					'rule_id' => array( 'type' => 'string', 'required' => true ),
				),
			)
		);

		// Backup routes.
		register_rest_route(
			self::API_NAMESPACE,
			'/backups',
			array(
				array(
					'methods'             => WP_REST_Server::READABLE,
					'callback'            => array( __CLASS__, 'get_backups' ),
					'permission_callback' => $permission,
					'args'                => array(
						'page'     => array( 'type' => 'integer', 'default' => 1, 'minimum' => 1 ),
						'per_page' => array( 'type' => 'integer', 'default' => 20, 'minimum' => 1, 'maximum' => 100 ),
					),
				),
				array(
					'methods'             => WP_REST_Server::CREATABLE,
					'callback'            => array( __CLASS__, 'create_backup' ),
					'permission_callback' => $permission,
					'args'                => array(
						'type' => array(
							'type'              => 'string',
							'enum'              => array( 'full', 'database', 'files' ),
							'default'           => 'full',
							'sanitize_callback' => 'sanitize_key',
						),
					),
				),
			)
		);

		register_rest_route(
			self::API_NAMESPACE,
			'/backups/(?P<id>\d+)/restore',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( __CLASS__, 'restore_backup' ),
				'permission_callback' => $permission,
				'args'                => array(
					'id' => array( 'type' => 'integer', 'required' => true ),
				),
			)
		);

		register_rest_route(
			self::API_NAMESPACE,
			'/backups/(?P<id>\d+)',
			array(
				'methods'             => WP_REST_Server::DELETABLE,
				'callback'            => array( __CLASS__, 'delete_backup' ),
				'permission_callback' => $permission,
				'args'                => array(
					'id' => array( 'type' => 'integer', 'required' => true ),
				),
			)
		);

		// Report routes.
		register_rest_route(
			self::API_NAMESPACE,
			'/reports',
			array(
				array(
					'methods'             => WP_REST_Server::READABLE,
					'callback'            => array( __CLASS__, 'get_reports' ),
					'permission_callback' => $permission,
					'args'                => array(
						'page'     => array( 'type' => 'integer', 'default' => 1, 'minimum' => 1 ),
						'per_page' => array( 'type' => 'integer', 'default' => 20, 'minimum' => 1, 'maximum' => 100 ),
					),
				),
				array(
					'methods'             => WP_REST_Server::CREATABLE,
					'callback'            => array( __CLASS__, 'generate_report' ),
					'permission_callback' => $permission,
					'args'                => array(
						'type'   => array(
							'type'              => 'string',
							'default'           => 'technical',
							'enum'              => array( 'technical', 'executive', 'compliance' ),
							'sanitize_callback' => 'sanitize_key',
						),
						'format' => array(
							'type'              => 'string',
							'default'           => 'html',
							'enum'              => array( 'html', 'json', 'csv' ),
							'sanitize_callback' => 'sanitize_key',
						),
					),
				),
			)
		);

		register_rest_route(
			self::API_NAMESPACE,
			'/reports/(?P<id>\d+)',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => array( __CLASS__, 'get_report' ),
				'permission_callback' => $permission,
				'args'                => array(
					'id' => array( 'type' => 'integer', 'required' => true ),
				),
			)
		);

		// Alert routes.
		register_rest_route(
			self::API_NAMESPACE,
			'/alerts/test',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( __CLASS__, 'test_alert_channel' ),
				'permission_callback' => $permission,
				'args'                => array(
					'channel' => array(
						'type'              => 'string',
						'required'          => true,
						'enum'              => array( 'email', 'slack', 'telegram', 'discord', 'webhook' ),
						'sanitize_callback' => 'sanitize_key',
					),
				),
			)
		);

		// Activity log route.
		register_rest_route(
			self::API_NAMESPACE,
			'/activity',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => array( __CLASS__, 'get_activity_log' ),
				'permission_callback' => $permission,
				'args'                => array(
					'page'           => array( 'type' => 'integer', 'default' => 1, 'minimum' => 1 ),
					'per_page'       => array( 'type' => 'integer', 'default' => 20, 'minimum' => 1, 'maximum' => 100 ),
					'severity'       => array(
						'type'              => 'string',
						'enum'              => array( 'critical', 'high', 'medium', 'low', 'info' ),
						'sanitize_callback' => 'sanitize_key',
					),
					'event_category' => array( 'type' => 'string', 'sanitize_callback' => 'sanitize_key' ),
					'date_from'      => array( 'type' => 'string', 'format' => 'date-time', 'sanitize_callback' => 'sanitize_text_field' ),
					'date_to'        => array( 'type' => 'string', 'format' => 'date-time', 'sanitize_callback' => 'sanitize_text_field' ),
				),
			)
		);

		// Intelligence route.
		register_rest_route(
			self::API_NAMESPACE,
			'/intelligence/analyze',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( __CLASS__, 'run_intelligence_analysis' ),
				'permission_callback' => $permission,
			)
		);
	}

	/**
	 * Permission check: must have manage_options capability.
	 *
	 * @return bool|WP_Error
	 */
	public static function check_permission() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return new WP_Error(
				'rest_forbidden',
				__( 'You do not have permission to access this endpoint.', 'wp-sentinel-security' ),
				array( 'status' => 403 )
			);
		}
		return true;
	}

	/**
	 * GET /sentinel/v1/status — Overall security status.
	 *
	 * @return WP_REST_Response
	 */
	public static function get_status() {
		$score     = Scoring_Engine::calculate_site_score();
		$last_scan = Sentinel_DB::get_latest_scan();

		return new WP_REST_Response(
			array(
				'score'          => $score,
				'last_scan'      => $last_scan,
				'server_info'    => Sentinel_Helper::get_server_info(),
			),
			200
		);
	}

	/**
	 * GET /sentinel/v1/scans — Paginated scan history.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return WP_REST_Response
	 */
	public static function get_scans( $request ) {
		$page   = max( 1, absint( $request->get_param( 'page' ) ) );
		$limit  = min( 100, max( 1, absint( $request->get_param( 'per_page' ) ) ) ) ?: 20;
		$offset = ( $page - 1 ) * $limit;
		$scans  = Sentinel_DB::get_scan_history( $limit, $offset );

		return new WP_REST_Response( $scans, 200 );
	}

	/**
	 * POST /sentinel/v1/scan — Start a new scan.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return WP_REST_Response|WP_Error
	 */
	public static function start_scan( $request ) {
		$allowed_types = array( 'quick', 'full', 'malware', 'integrity' );
		$scan_type     = sanitize_key( $request->get_param( 'scan_type' ) ?: 'quick' );

		if ( ! in_array( $scan_type, $allowed_types, true ) ) {
			return new WP_Error( 'invalid_scan_type', __( 'Invalid scan type.', 'wp-sentinel-security' ), array( 'status' => 400 ) );
		}

		if ( ! class_exists( 'Scanner_Engine' ) ) {
			require_once SENTINEL_PLUGIN_DIR . 'includes/modules/scanner/class-scanner-engine.php';
		}

		$settings = get_option( 'sentinel_settings', array() );
		$engine   = new Scanner_Engine( $settings );
		$engine->init();

		$scan_id = $engine->run_scan( $scan_type, 'rest_api' );

		return new WP_REST_Response( array( 'scan_id' => $scan_id ), 201 );
	}

	/**
	 * GET /sentinel/v1/vulnerabilities — List vulnerabilities with optional filters.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return WP_REST_Response
	 */
	public static function get_vulnerabilities( $request ) {
		$filters = array();

		foreach ( array( 'severity', 'component_type', 'status' ) as $param ) {
			$value = $request->get_param( $param );
			if ( $value ) {
				$filters[ $param ] = sanitize_text_field( $value );
			}
		}

		$vulns = Sentinel_DB::get_open_vulnerabilities( $filters );

		return new WP_REST_Response( $vulns, 200 );
	}

	/**
	 * PUT /sentinel/v1/vulnerabilities/{id} — Update vulnerability status.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return WP_REST_Response|WP_Error
	 */
	public static function update_vulnerability( $request ) {
		global $wpdb;

		$id     = absint( $request->get_param( 'id' ) );
		$status = sanitize_key( $request->get_param( 'status' ) );

		if ( ! $id ) {
			return new WP_Error( 'invalid_id', __( 'Invalid vulnerability ID.', 'wp-sentinel-security' ), array( 'status' => 400 ) );
		}

		$allowed_statuses = array( 'open', 'fixed', 'ignored', 'false_positive' );
		if ( ! in_array( $status, $allowed_statuses, true ) ) {
			return new WP_Error( 'invalid_status', __( 'Invalid vulnerability status.', 'wp-sentinel-security' ), array( 'status' => 400 ) );
		}

		$update_data = array( 'status' => $status );
		$update_formats = array( '%s' );

		if ( in_array( $status, array( 'fixed', 'ignored', 'false_positive' ), true ) ) {
			$update_data['resolved_at'] = current_time( 'mysql' );
			$update_formats[]           = '%s';
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$updated = $wpdb->update(
			"{$wpdb->prefix}sentinel_vulnerabilities",
			$update_data,
			array( 'id' => $id ),
			$update_formats,
			array( '%d' )
		);

		if ( false === $updated ) {
			return new WP_Error( 'update_failed', __( 'Failed to update vulnerability.', 'wp-sentinel-security' ), array( 'status' => 500 ) );
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$vuln = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM {$wpdb->prefix}sentinel_vulnerabilities WHERE id = %d",
				$id
			)
		);

		return new WP_REST_Response( $vuln, 200 );
	}

	// -------------------------------------------------------------------------
	// Hardening endpoints
	// -------------------------------------------------------------------------

	/**
	 * GET /sentinel/v1/hardening — List all hardening checks with status.
	 *
	 * @return WP_REST_Response
	 */
	public static function get_hardening() {
		$settings = get_option( 'sentinel_settings', array() );
		$engine   = self::get_hardening_engine( $settings );

		return new WP_REST_Response(
			array(
				'checks' => $engine->get_all_checks(),
				'score'  => $engine->get_hardening_score(),
			),
			200
		);
	}

	/**
	 * POST /sentinel/v1/hardening/{rule_id}/apply — Apply a hardening rule.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return WP_REST_Response|WP_Error
	 */
	public static function apply_hardening_rule( $request ) {
		$rule_id  = sanitize_key( $request->get_param( 'rule_id' ) );
		$settings = get_option( 'sentinel_settings', array() );
		$engine   = self::get_hardening_engine( $settings );
		$result   = $engine->apply_check( $rule_id );

		if ( isset( $result['status'] ) && 'error' === $result['status'] ) {
			return new WP_Error( 'hardening_error', $result['message'], array( 'status' => 400 ) );
		}

		return new WP_REST_Response(
			array(
				'result'       => $result,
				'check_status' => $engine->get_check_status( $rule_id ),
				'score'        => $engine->get_hardening_score(),
			),
			200
		);
	}

	/**
	 * POST /sentinel/v1/hardening/{rule_id}/revert — Revert a hardening rule.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return WP_REST_Response|WP_Error
	 */
	public static function revert_hardening_rule( $request ) {
		$rule_id  = sanitize_key( $request->get_param( 'rule_id' ) );
		$settings = get_option( 'sentinel_settings', array() );
		$engine   = self::get_hardening_engine( $settings );
		$result   = $engine->revert_check( $rule_id );

		if ( isset( $result['status'] ) && 'error' === $result['status'] ) {
			return new WP_Error( 'hardening_error', $result['message'], array( 'status' => 400 ) );
		}

		return new WP_REST_Response(
			array(
				'result'       => $result,
				'check_status' => $engine->get_check_status( $rule_id ),
				'score'        => $engine->get_hardening_score(),
			),
			200
		);
	}

	// -------------------------------------------------------------------------
	// Backup endpoints
	// -------------------------------------------------------------------------

	/**
	 * GET /sentinel/v1/backups — List all backups.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return WP_REST_Response
	 */
	public static function get_backups( $request ) {
		$page     = absint( $request->get_param( 'page' ) );
		$per_page = absint( $request->get_param( 'per_page' ) );

		$engine = self::get_backup_engine();
		$data   = $engine->get_backups( $page, $per_page );

		return new WP_REST_Response( $data, 200 );
	}

	/**
	 * POST /sentinel/v1/backups — Create a new backup.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return WP_REST_Response|WP_Error
	 */
	public static function create_backup( $request ) {
		$type   = sanitize_text_field( $request->get_param( 'type' ) );
		$engine = self::get_backup_engine();
		$result = $engine->create_backup( $type );

		if ( is_wp_error( $result ) ) {
			return new WP_Error( 'backup_failed', $result->get_error_message(), array( 'status' => 500 ) );
		}

		return new WP_REST_Response( array( 'backup_id' => $result ), 201 );
	}

	/**
	 * POST /sentinel/v1/backups/{id}/restore — Restore a backup.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return WP_REST_Response|WP_Error
	 */
	public static function restore_backup( $request ) {
		$id     = absint( $request->get_param( 'id' ) );
		$engine = self::get_backup_engine();
		$result = $engine->restore_backup( $id );

		if ( is_wp_error( $result ) ) {
			return new WP_Error( 'restore_failed', $result->get_error_message(), array( 'status' => 500 ) );
		}

		return new WP_REST_Response( array( 'message' => __( 'Backup restored successfully.', 'wp-sentinel-security' ) ), 200 );
	}

	/**
	 * DELETE /sentinel/v1/backups/{id} — Delete a backup.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return WP_REST_Response|WP_Error
	 */
	public static function delete_backup( $request ) {
		$id     = absint( $request->get_param( 'id' ) );
		$engine = self::get_backup_engine();
		$result = $engine->delete_backup( $id );

		if ( is_wp_error( $result ) ) {
			return new WP_Error( 'delete_failed', $result->get_error_message(), array( 'status' => 500 ) );
		}

		return new WP_REST_Response( array( 'message' => __( 'Backup deleted successfully.', 'wp-sentinel-security' ) ), 200 );
	}

	// -------------------------------------------------------------------------
	// Report endpoints
	// -------------------------------------------------------------------------

	/**
	 * GET /sentinel/v1/reports — List all reports.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return WP_REST_Response
	 */
	public static function get_reports( $request ) {
		$page     = absint( $request->get_param( 'page' ) );
		$per_page = absint( $request->get_param( 'per_page' ) );

		$data = Sentinel_DB::get_reports( $page, $per_page );

		return new WP_REST_Response( $data, 200 );
	}

	/**
	 * POST /sentinel/v1/reports — Generate a report.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return WP_REST_Response|WP_Error
	 */
	public static function generate_report( $request ) {
		$type     = sanitize_text_field( $request->get_param( 'type' ) );
		$format   = sanitize_text_field( $request->get_param( 'format' ) );
		$settings = get_option( 'sentinel_settings', array() );
		$engine   = self::get_report_engine( $settings );
		$result   = $engine->generate_report( $type, $format );

		if ( is_wp_error( $result ) ) {
			return new WP_Error( 'report_failed', $result->get_error_message(), array( 'status' => 500 ) );
		}

		return new WP_REST_Response( array( 'report_id' => $result ), 201 );
	}

	/**
	 * GET /sentinel/v1/reports/{id} — Get a specific report.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return WP_REST_Response|WP_Error
	 */
	public static function get_report( $request ) {
		global $wpdb;

		$id = absint( $request->get_param( 'id' ) );

		if ( ! $id ) {
			return new WP_Error( 'invalid_id', __( 'Invalid report ID.', 'wp-sentinel-security' ), array( 'status' => 400 ) );
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$report = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM {$wpdb->prefix}sentinel_reports WHERE id = %d",
				$id
			)
		);

		if ( ! $report ) {
			return new WP_Error( 'not_found', __( 'Report not found.', 'wp-sentinel-security' ), array( 'status' => 404 ) );
		}

		return new WP_REST_Response( $report, 200 );
	}

	// -------------------------------------------------------------------------
	// Alert endpoints
	// -------------------------------------------------------------------------

	/**
	 * POST /sentinel/v1/alerts/test — Test an alert channel.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return WP_REST_Response|WP_Error
	 */
	public static function test_alert_channel( $request ) {
		$channel  = sanitize_text_field( $request->get_param( 'channel' ) );
		$settings = get_option( 'sentinel_settings', array() );

		$allowed = array( 'email', 'slack', 'telegram', 'discord', 'webhook' );
		if ( ! in_array( $channel, $allowed, true ) ) {
			return new WP_Error( 'invalid_channel', __( 'Unknown alert channel.', 'wp-sentinel-security' ), array( 'status' => 400 ) );
		}

		$dir = SENTINEL_PLUGIN_DIR . 'includes/modules/alerts/';
		$channel_map = array();

		if ( ! class_exists( 'Alert_Email' ) )    { require_once $dir . 'class-alert-email.php';    }
		if ( ! class_exists( 'Alert_Slack' ) )    { require_once $dir . 'class-alert-slack.php';    }
		if ( ! class_exists( 'Alert_Telegram' ) ) { require_once $dir . 'class-alert-telegram.php'; }
		if ( ! class_exists( 'Alert_Discord' ) )  { require_once $dir . 'class-alert-discord.php';  }
		if ( ! class_exists( 'Alert_Webhook' ) )  { require_once $dir . 'class-alert-webhook.php';  }

		$channel_map = array(
			'email'    => new Alert_Email( $settings ),
			'slack'    => new Alert_Slack( $settings ),
			'telegram' => new Alert_Telegram( $settings ),
			'discord'  => new Alert_Discord( $settings ),
			'webhook'  => new Alert_Webhook( $settings ),
		);

		$result = $channel_map[ $channel ]->send(
			__( 'WP Sentinel Security — Test Alert', 'wp-sentinel-security' ),
			__( 'This is a test alert from WP Sentinel Security via REST API.', 'wp-sentinel-security' ),
			array( 'severity' => 'info' )
		);

		if ( is_wp_error( $result ) || false === $result ) {
			$msg = is_wp_error( $result ) ? $result->get_error_message() : __( 'Alert could not be sent.', 'wp-sentinel-security' );
			return new WP_Error( 'send_failed', $msg, array( 'status' => 500 ) );
		}

		return new WP_REST_Response( array( 'message' => __( 'Test alert sent successfully.', 'wp-sentinel-security' ) ), 200 );
	}

	// -------------------------------------------------------------------------
	// Activity log endpoint
	// -------------------------------------------------------------------------

	/**
	 * GET /sentinel/v1/activity — Get the activity log (paginated, filterable).
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return WP_REST_Response
	 */
	public static function get_activity_log( $request ) {
		$filters = array();

		foreach ( array( 'severity', 'event_category', 'date_from', 'date_to' ) as $param ) {
			$value = $request->get_param( $param );
			if ( $value ) {
				$filters[ $param ] = sanitize_text_field( $value );
			}
		}

		$page     = absint( $request->get_param( 'page' ) );
		$per_page = absint( $request->get_param( 'per_page' ) );

		$data = Sentinel_DB::get_activity_log( $filters, $page, $per_page );

		return new WP_REST_Response( $data, 200 );
	}

	// -------------------------------------------------------------------------
	// Intelligence endpoint
	// -------------------------------------------------------------------------

	/**
	 * POST /sentinel/v1/intelligence/analyze — Run intelligence analysis.
	 *
	 * @return WP_REST_Response
	 */
	public static function run_intelligence_analysis() {
		if ( ! class_exists( 'Intelligence_Engine' ) ) {
			$dir = SENTINEL_PLUGIN_DIR . 'includes/modules/intelligence/';
			require_once $dir . 'class-context-analyzer.php';
			require_once $dir . 'class-environment-fingerprint.php';
			require_once $dir . 'class-attack-surface-mapper.php';
			require_once $dir . 'class-risk-context-score.php';
			require_once $dir . 'class-intelligence-engine.php';
		}

		$settings = get_option( 'sentinel_settings', array() );
		$engine   = new Intelligence_Engine( $settings );
		$engine->init();
		$data = $engine->run_full_analysis( true );

		return new WP_REST_Response( $data, 200 );
	}

	// -------------------------------------------------------------------------
	// Private factory helpers
	// -------------------------------------------------------------------------

	/**
	 * Instantiate and init the Hardening_Engine.
	 *
	 * @param array $settings Plugin settings.
	 * @return Hardening_Engine
	 */
	private static function get_hardening_engine( $settings ) {
		if ( ! class_exists( 'Hardening_Engine' ) ) {
			$dir = SENTINEL_PLUGIN_DIR . 'includes/modules/hardening/';
			require_once $dir . 'class-file-hardening.php';
			require_once $dir . 'class-wp-config-hardening.php';
			require_once $dir . 'class-user-hardening.php';
			require_once $dir . 'class-database-hardening.php';
			require_once $dir . 'class-api-hardening.php';
			require_once $dir . 'class-hardening-engine.php';
		}
		$engine = new Hardening_Engine( $settings );
		$engine->init();
		return $engine;
	}

	/**
	 * Instantiate and init the Backup_Engine.
	 *
	 * @return Backup_Engine
	 */
	private static function get_backup_engine() {
		if ( ! class_exists( 'Backup_Engine' ) ) {
			$dir = SENTINEL_PLUGIN_DIR . 'includes/modules/backup/';
			require_once $dir . 'class-backup-database.php';
			require_once $dir . 'class-backup-files.php';
			require_once $dir . 'class-backup-engine.php';
		}
		$settings = get_option( 'sentinel_settings', array() );
		$engine   = new Backup_Engine( $settings );
		$engine->init();
		return $engine;
	}

	/**
	 * Instantiate and init the Report_Engine.
	 *
	 * @param array $settings Plugin settings.
	 * @return Report_Engine
	 */
	private static function get_report_engine( $settings ) {
		if ( ! class_exists( 'Report_Engine' ) ) {
			$dir = SENTINEL_PLUGIN_DIR . 'includes/modules/reports/';
			require_once $dir . 'class-report-json-renderer.php';
			require_once $dir . 'class-report-csv-renderer.php';
			require_once $dir . 'class-report-html-renderer.php';
			require_once $dir . 'class-report-engine.php';
		}
		$engine = new Report_Engine( $settings );
		$engine->init();
		return $engine;
	}
}
