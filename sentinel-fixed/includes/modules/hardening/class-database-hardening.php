<?php
/**
 * Database Hardening — Audits database configuration for security risks.
 *
 * This class is intentionally read-only: it reports on risks that require
 * manual DBA action (table-prefix changes, privilege reduction, password
 * complexity).  Apply methods log the recommendation and return actionable
 * guidance rather than making destructive or irreversible changes.
 *
 * @package WP_Sentinel_Security
 * @since   2.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Database_Hardening
 *
 * All status methods return: array('status' => string, 'details' => string)
 * where status is 'applied' | 'not_applied' | 'partial'.
 *
 * Apply methods return: array('status' => string, 'message' => string)
 * where status is 'manual_required' (no destructive auto-changes are made).
 */
class Database_Hardening {

	/**
	 * The default WordPress table prefix — treated as risky.
	 *
	 * @var string
	 */
	const DEFAULT_PREFIX = 'wp_';

	/**
	 * Minimum recommended DB_PASSWORD length.
	 *
	 * @var int
	 */
	const MIN_PASSWORD_LENGTH = 16;

	// =========================================================================
	// 1. Table prefix
	// =========================================================================

	/**
	 * Apply: inform the admin that the table prefix should be changed manually.
	 *
	 * Changing the prefix requires updating every table name, the wp-config.php
	 * $table_prefix variable, and all option/user-meta keys that store the prefix.
	 * This is too risky to automate safely, so we guide the admin instead.
	 *
	 * @return array{status: string, message: string}
	 */
	public function check_table_prefix() {
		global $wpdb;

		if ( $wpdb->prefix === self::DEFAULT_PREFIX ) {
			update_option(
				'sentinel_hardening_check_table_prefix_guidance',
				__(
					'Your table prefix is "wp_". To change it: 1) Put the site in maintenance mode. 2) Rename each table in phpMyAdmin. 3) Update $table_prefix in wp-config.php. 4) Update usermeta and options rows that contain the old prefix. Consider using a migration plugin for safety.',
					'wp-sentinel-security'
				)
			);

			return array(
				'status'  => 'manual_required',
				'message' => __(
					'The default "wp_" prefix is in use. Changing it requires manual database migration — see the guidance stored in Settings.',
					'wp-sentinel-security'
				),
			);
		}

		return array(
			'status'  => 'ok',
			'message' => __( 'Your table prefix is already non-default — no action needed.', 'wp-sentinel-security' ),
		);
	}

	/**
	 * Status: check whether the table prefix is the risky default 'wp_'.
	 *
	 * @return array{status: string, details: string}
	 */
	public function status_check_table_prefix() {
		global $wpdb;

		if ( $wpdb->prefix === self::DEFAULT_PREFIX ) {
			return array(
				'status'  => 'not_applied',
				/* translators: %s: current table prefix */
				'details' => sprintf(
					__( 'Table prefix is "%s" (the default). Using a custom prefix reduces enumeration risk.', 'wp-sentinel-security' ),
					esc_html( $wpdb->prefix )
				),
			);
		}

		return array(
			'status'  => 'applied',
			/* translators: %s: current table prefix */
			'details' => sprintf(
				__( 'Table prefix is "%s" (non-default — good).', 'wp-sentinel-security' ),
				esc_html( $wpdb->prefix )
			),
		);
	}

	// =========================================================================
	// 2. Database privileges
	// =========================================================================

	/**
	 * Apply: advise the admin to reduce MySQL privileges for the WP DB user.
	 *
	 * An automatically executed REVOKE would be unsafe because WordPress
	 * needs ALTER and CREATE during upgrades.  We report the current grants
	 * and recommend the principle of least privilege instead.
	 *
	 * @return array{status: string, message: string}
	 */
	public function check_db_privileges() {
		$grants = $this->get_current_grants();

		$excessive = $this->detect_excessive_privileges( $grants );

		if ( ! empty( $excessive ) ) {
			update_option(
				'sentinel_hardening_check_db_privileges_guidance',
				sprintf(
					/* translators: %s: comma-separated list of excessive privileges */
					__(
						'The database user has the following excessive privileges: %s. Consider removing them and granting only SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, ALTER, INDEX.',
						'wp-sentinel-security'
					),
					implode( ', ', $excessive )
				)
			);

			return array(
				'status'  => 'manual_required',
				/* translators: %s: comma-separated list of privileges */
				'message' => sprintf(
					__( 'Excessive DB privileges detected: %s. Manual REVOKE via your database manager is required.', 'wp-sentinel-security' ),
					implode( ', ', array_map( 'esc_html', $excessive ) )
				),
			);
		}

		return array(
			'status'  => 'ok',
			'message' => __( 'No obviously excessive database privileges were detected.', 'wp-sentinel-security' ),
		);
	}

	/**
	 * Status: report whether the DB user has excessive privileges.
	 *
	 * @return array{status: string, details: string}
	 */
	public function status_check_db_privileges() {
		$grants    = $this->get_current_grants();
		$excessive = $this->detect_excessive_privileges( $grants );

		if ( ! empty( $excessive ) ) {
			return array(
				'status'  => 'not_applied',
				/* translators: %s: list of excessive privileges */
				'details' => sprintf(
					__( 'Excessive privileges detected: %s. Manual intervention required.', 'wp-sentinel-security' ),
					implode( ', ', array_map( 'esc_html', $excessive ) )
				),
			);
		}

		if ( empty( $grants ) ) {
			return array(
				'status'  => 'partial',
				'details' => __( 'Could not retrieve database grants. Verify permissions manually.', 'wp-sentinel-security' ),
			);
		}

		return array(
			'status'  => 'applied',
			'details' => __( 'Database user privileges appear reasonable.', 'wp-sentinel-security' ),
		);
	}

	// =========================================================================
	// 3. Database password strength
	// =========================================================================

	/**
	 * Apply: check DB_PASSWORD strength and advise the admin if it is weak.
	 *
	 * Passwords are never stored or logged — only their length and composition
	 * are examined.
	 *
	 * @return array{status: string, message: string}
	 */
	public function check_db_password_strength() {
		$strength = $this->evaluate_password_strength();

		if ( 'strong' === $strength ) {
			return array(
				'status'  => 'ok',
				'message' => __( 'Database password meets minimum strength requirements.', 'wp-sentinel-security' ),
			);
		}

		return array(
			'status'  => 'manual_required',
			/* translators: %d: minimum recommended password length */
			'message' => sprintf(
				__(
					'Database password is weak. Please update it to at least %d characters with mixed case, numbers, and symbols, then update DB_PASSWORD in wp-config.php.',
					'wp-sentinel-security'
				),
				self::MIN_PASSWORD_LENGTH
			),
		);
	}

	/**
	 * Status: report current DB_PASSWORD strength level.
	 *
	 * @return array{status: string, details: string}
	 */
	public function status_check_db_password_strength() {
		$strength = $this->evaluate_password_strength();

		if ( 'strong' === $strength ) {
			return array(
				'status'  => 'applied',
				'details' => __( 'Database password meets the minimum strength requirements.', 'wp-sentinel-security' ),
			);
		}

		if ( 'moderate' === $strength ) {
			return array(
				'status'  => 'partial',
				/* translators: %d: minimum password length */
				'details' => sprintf(
					__( 'Database password is moderate. Recommend at least %d characters with full character class mix.', 'wp-sentinel-security' ),
					self::MIN_PASSWORD_LENGTH
				),
			);
		}

		return array(
			'status'  => 'not_applied',
			/* translators: %d: minimum password length */
			'details' => sprintf(
				__( 'Database password is weak (fewer than %d characters or missing character classes).', 'wp-sentinel-security' ),
				self::MIN_PASSWORD_LENGTH
			),
		);
	}

	// =========================================================================
	// Private helpers
	// =========================================================================

	/**
	 * Retrieve SHOW GRANTS output for the current MySQL user.
	 *
	 * @return string[] Array of grant strings, empty on failure.
	 */
	private function get_current_grants() {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$rows = $wpdb->get_col( 'SHOW GRANTS FOR CURRENT_USER' ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared

		return is_array( $rows ) ? $rows : array();
	}

	/**
	 * Parse grant strings and return a list of excessive privilege names.
	 *
	 * Privileges considered excessive for a standard WordPress installation:
	 *   FILE, SUPER, PROCESS, SHUTDOWN, RELOAD, GRANT OPTION, ALL PRIVILEGES.
	 *
	 * @param string[] $grants Raw SHOW GRANTS output rows.
	 * @return string[] Names of excessive privileges found.
	 */
	private function detect_excessive_privileges( array $grants ) {
		$excessive_list = array(
			'FILE',
			'SUPER',
			'PROCESS',
			'SHUTDOWN',
			'RELOAD',
			'GRANT OPTION',
			'ALL PRIVILEGES',
		);

		$found = array();

		foreach ( $grants as $grant_row ) {
			foreach ( $excessive_list as $priv ) {
				if ( false !== stripos( $grant_row, $priv ) ) {
					$found[] = $priv;
				}
			}
		}

		return array_unique( $found );
	}

	/**
	 * Evaluate the strength of the DB_PASSWORD constant without storing it.
	 *
	 * Strength levels:
	 *   'strong'   — ≥ MIN_PASSWORD_LENGTH chars with all 4 character classes
	 *   'moderate' — ≥ 8 chars with at least 3 character classes
	 *   'weak'     — anything else
	 *
	 * @return string 'strong' | 'moderate' | 'weak'
	 */
	private function evaluate_password_strength() {
		if ( ! defined( 'DB_PASSWORD' ) ) {
			return 'weak';
		}

		$password = DB_PASSWORD;
		$length   = strlen( $password );

		$has_upper   = (bool) preg_match( '/[A-Z]/', $password );
		$has_lower   = (bool) preg_match( '/[a-z]/', $password );
		$has_digit   = (bool) preg_match( '/[0-9]/', $password );
		$has_special = (bool) preg_match( '/[^A-Za-z0-9]/', $password );

		$classes_met = (int) $has_upper + (int) $has_lower + (int) $has_digit + (int) $has_special;

		if ( $length >= self::MIN_PASSWORD_LENGTH && 4 === $classes_met ) {
			return 'strong';
		}

		if ( $length >= 8 && $classes_met >= 3 ) {
			return 'moderate';
		}

		return 'weak';
	}
}
