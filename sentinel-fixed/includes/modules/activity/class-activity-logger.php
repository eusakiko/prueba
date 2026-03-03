<?php
/**
 * Activity logger.
 *
 * Hooks into WordPress core events and custom sentinel hooks to maintain
 * an audit trail in the sentinel_activity_log table.
 *
 * @package WP_Sentinel_Security
 * @since   2.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Activity_Logger
 */
class Activity_Logger {

	/**
	 * Register WordPress hooks.
	 *
	 * @return void
	 */
	public function init() {
		// Core authentication events.
		add_action( 'wp_login',        array( $this, 'on_login' ), 10, 2 );
		add_action( 'wp_login_failed', array( $this, 'on_login_failed' ), 10, 1 );

		// User management events.
		add_action( 'set_user_role',  array( $this, 'on_user_role_change' ), 10, 3 );
		add_action( 'delete_user',    array( $this, 'on_user_deleted' ), 10, 1 );

		// Plugin/theme events.
		add_action( 'activated_plugin',   array( $this, 'on_plugin_activated' ), 10, 1 );
		add_action( 'deactivated_plugin', array( $this, 'on_plugin_deactivated' ), 10, 1 );
		add_action( 'switch_theme',       array( $this, 'on_theme_switched' ), 10, 1 );

		// Custom sentinel events.
		add_action( 'sentinel_scan_complete',       array( $this, 'on_scan_complete' ), 10, 1 );
		add_action( 'sentinel_hardening_applied',   array( $this, 'on_hardening_applied' ), 10, 1 );
		add_action( 'sentinel_backup_created',      array( $this, 'on_backup_created' ), 10, 1 );
		add_action( 'sentinel_malware_detected',    array( $this, 'on_malware_detected' ), 10, 1 );
	}

	/**
	 * Log a successful login.
	 *
	 * @param string  $user_login Username.
	 * @param WP_User $user       User object.
	 * @return void
	 */
	public function on_login( $user_login, $user ) {
		self::log(
			'user_login',
			'authentication',
			'info',
			sprintf(
				/* translators: %s: Username */
				__( 'User "%s" logged in successfully.', 'wp-sentinel-security' ),
				sanitize_user( $user_login )
			),
			array( 'user_id' => $user->ID )
		);
	}

	/**
	 * Log a failed login attempt.
	 *
	 * @param string $username Attempted username.
	 * @return void
	 */
	public function on_login_failed( $username ) {
		self::log(
			'login_failed',
			'authentication',
			'medium',
			sprintf(
				/* translators: %s: Username */
				__( 'Failed login attempt for user "%s".', 'wp-sentinel-security' ),
				sanitize_user( $username )
			),
			array( 'attempted_username' => sanitize_user( $username ) )
		);
	}

	/**
	 * Log a user role change.
	 *
	 * @param int    $user_id   User ID.
	 * @param string $new_role  New role slug.
	 * @param array  $old_roles Previous roles.
	 * @return void
	 */
	public function on_user_role_change( $user_id, $new_role, $old_roles ) {
		self::log(
			'user_role_changed',
			'user_management',
			'medium',
			sprintf(
				/* translators: 1: User ID, 2: New role */
				__( 'User #%1$d role changed to "%2$s".', 'wp-sentinel-security' ),
				absint( $user_id ),
				sanitize_text_field( $new_role )
			),
			array(
				'target_user_id' => absint( $user_id ),
				'new_role'       => sanitize_text_field( $new_role ),
				'old_roles'      => array_map( 'sanitize_text_field', (array) $old_roles ),
			)
		);
	}

	/**
	 * Log a user deletion.
	 *
	 * @param int $user_id Deleted user ID.
	 * @return void
	 */
	public function on_user_deleted( $user_id ) {
		self::log(
			'user_deleted',
			'user_management',
			'high',
			sprintf(
				/* translators: %d: User ID */
				__( 'User #%d was deleted.', 'wp-sentinel-security' ),
				absint( $user_id )
			),
			array( 'deleted_user_id' => absint( $user_id ) )
		);
	}

	/**
	 * Log plugin activation.
	 *
	 * @param string $plugin Plugin file path.
	 * @return void
	 */
	public function on_plugin_activated( $plugin ) {
		self::log(
			'plugin_activated',
			'plugin',
			'info',
			sprintf(
				/* translators: %s: Plugin file */
				__( 'Plugin activated: %s', 'wp-sentinel-security' ),
				sanitize_text_field( $plugin )
			),
			array( 'plugin' => sanitize_text_field( $plugin ) )
		);
	}

	/**
	 * Log plugin deactivation.
	 *
	 * @param string $plugin Plugin file path.
	 * @return void
	 */
	public function on_plugin_deactivated( $plugin ) {
		self::log(
			'plugin_deactivated',
			'plugin',
			'info',
			sprintf(
				/* translators: %s: Plugin file */
				__( 'Plugin deactivated: %s', 'wp-sentinel-security' ),
				sanitize_text_field( $plugin )
			),
			array( 'plugin' => sanitize_text_field( $plugin ) )
		);
	}

	/**
	 * Log a theme switch.
	 *
	 * @param string $new_name Name of the newly activated theme.
	 * @return void
	 */
	public function on_theme_switched( $new_name ) {
		self::log(
			'theme_switched',
			'theme',
			'info',
			sprintf(
				/* translators: %s: Theme name */
				__( 'Theme switched to "%s".', 'wp-sentinel-security' ),
				sanitize_text_field( $new_name )
			),
			array( 'new_theme' => sanitize_text_field( $new_name ) )
		);
	}

	/**
	 * Log sentinel scan completion.
	 *
	 * @param array $scan_data Scan result data.
	 * @return void
	 */
	public function on_scan_complete( $scan_data ) {
		$found = isset( $scan_data['vulnerabilities_found'] ) ? absint( $scan_data['vulnerabilities_found'] ) : 0;
		self::log(
			'sentinel_scan_complete',
			'scanner',
			'info',
			sprintf(
				/* translators: %d: Number of vulnerabilities found */
				__( 'Security scan completed. %d vulnerabilities found.', 'wp-sentinel-security' ),
				$found
			),
			is_array( $scan_data ) ? $scan_data : array()
		);
	}

	/**
	 * Log sentinel hardening application.
	 *
	 * @param array $hardening_data Hardening event data.
	 * @return void
	 */
	public function on_hardening_applied( $hardening_data ) {
		self::log(
			'sentinel_hardening_applied',
			'hardening',
			'medium',
			__( 'Security hardening configuration was applied.', 'wp-sentinel-security' ),
			is_array( $hardening_data ) ? $hardening_data : array()
		);
	}

	/**
	 * Log backup creation.
	 *
	 * @param array $backup_data Backup event data.
	 * @return void
	 */
	public function on_backup_created( $backup_data ) {
		self::log(
			'sentinel_backup_created',
			'backup',
			'info',
			__( 'A site backup was created successfully.', 'wp-sentinel-security' ),
			is_array( $backup_data ) ? $backup_data : array()
		);
	}

	/**
	 * Log malware detection.
	 *
	 * @param array $malware_data Malware detection data.
	 * @return void
	 */
	public function on_malware_detected( $malware_data ) {
		self::log(
			'sentinel_malware_detected',
			'scanner',
			'critical',
			__( 'Potential malware was detected on the site.', 'wp-sentinel-security' ),
			is_array( $malware_data ) ? $malware_data : array()
		);
	}

	/**
	 * Insert an activity log entry into the database.
	 *
	 * @param string $event_type     Machine-readable event identifier.
	 * @param string $event_category Grouping category.
	 * @param string $severity       One of: critical, high, medium, low, info.
	 * @param string $description    Human-readable description.
	 * @param array  $metadata       Additional contextual data.
	 * @return int|false Inserted row ID on success, false on failure.
	 */
	public static function log( $event_type, $event_category, $severity, $description, $metadata = array() ) {
		global $wpdb;

		$ip_address = class_exists( 'Sentinel_Helper' ) ? Sentinel_Helper::get_client_ip() : '';
		$user_agent = sanitize_text_field( $_SERVER['HTTP_USER_AGENT'] ?? '' ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotValidated

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$result = $wpdb->insert(
			"{$wpdb->prefix}sentinel_activity_log",
			array(
				'user_id'        => get_current_user_id(),
				'event_type'     => sanitize_text_field( $event_type ),
				'event_category' => sanitize_text_field( $event_category ),
				'severity'       => sanitize_text_field( $severity ),
				'description'    => sanitize_text_field( $description ),
				'ip_address'     => sanitize_text_field( $ip_address ),
				'user_agent'     => $user_agent,
				'object_type'    => sanitize_text_field( $metadata['object_type'] ?? '' ),
				'object_id'      => sanitize_text_field( $metadata['object_id'] ?? '' ),
				'metadata'       => wp_json_encode( $metadata ),
				'created_at'     => current_time( 'mysql' ),
			),
			array( '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s' )
		);

		return $result ? $wpdb->insert_id : false;
	}
}
