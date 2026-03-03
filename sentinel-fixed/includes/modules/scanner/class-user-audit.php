<?php
/**
 * User Audit Scanner.
 *
 * Checks WordPress user accounts for security issues.
 *
 * @package WP_Sentinel_Security
 * @since   1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class User_Audit
 */
class User_Audit {

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
	 * Run the user audit.
	 *
	 * @return array Array of vulnerability data arrays.
	 */
	public function scan() {
		$vulnerabilities = array();

		// Check for 'admin' username with ID 1.
		$admin_user = get_user_by( 'login', 'admin' );
		if ( $admin_user && 1 === (int) $admin_user->ID ) {
			$vulnerabilities[] = $this->build(
				'user-admin-username',
				'Default "admin" username still in use',
				'The user with username "admin" and ID 1 exists. This is the default WordPress administrator username and is a common target for brute-force attacks.',
				'medium',
				5.3,
				'Create a new administrator account with a unique username and delete the "admin" account.'
			);
		}

		// Count administrators.
		$admins      = get_users( array( 'role' => 'administrator' ) );
		$admin_count = count( $admins );

		if ( $admin_count > 5 ) {
			$vulnerabilities[] = $this->build(
				'user-excessive-admins-high',
				sprintf( 'Excessive number of administrators: %d', $admin_count ),
				sprintf( 'There are %d administrator accounts. Each administrator can make unrestricted changes to the site.', $admin_count ),
				'high',
				7.2,
				'Review all administrator accounts and demote or remove any that do not require full administrator access.'
			);
		} elseif ( $admin_count > 3 ) {
			$vulnerabilities[] = $this->build(
				'user-excessive-admins-medium',
				sprintf( 'Multiple administrator accounts: %d', $admin_count ),
				sprintf( 'There are %d administrator accounts. Consider whether all of them require full administrator privileges.', $admin_count ),
				'medium',
				5.3,
				'Review administrator accounts and apply the principle of least privilege.'
			);
		}

		// Check for inactive administrators (no login in 90+ days).
		$ninety_days_ago = gmdate( 'Y-m-d H:i:s', strtotime( '-90 days' ) );
		foreach ( $admins as $admin ) {
			$last_login = get_user_meta( $admin->ID, 'last_login', true );

			if ( ! $last_login ) {
				// Use user_registered as fallback.
				$last_activity = $admin->user_registered;
			} else {
				$last_activity = $last_login;
			}

			if ( $last_activity && $last_activity < $ninety_days_ago ) {
				$vulnerabilities[] = $this->build(
					'user-inactive-admin-' . $admin->ID,
					sprintf( 'Inactive administrator account: %s', $admin->user_login ),
					sprintf( 'Administrator "%s" has not logged in since %s (over 90 days ago).', $admin->user_login, $last_activity ),
					'medium',
					5.3,
					sprintf( 'Review and deactivate the administrator account for "%s" if it is no longer needed.', $admin->user_login )
				);
			}
		}

		// Check for open user registration.
		if ( get_option( 'users_can_register' ) ) {
			$vulnerabilities[] = $this->build(
				'user-open-registration',
				'User registration is open',
				'Anyone can register an account on your site. This increases the attack surface for privilege escalation vulnerabilities.',
				'medium',
				5.3,
				'Disable user registration in Settings → General unless it is specifically required.'
			);
		}

		// Check default role for new users.
		$default_role = get_option( 'default_role', 'subscriber' );
		if ( in_array( $default_role, array( 'administrator', 'editor' ), true ) ) {
			$vulnerabilities[] = $this->build(
				'user-high-default-role',
				sprintf( 'Dangerous default user role: %s', $default_role ),
				sprintf( 'New users are automatically assigned the "%s" role, which has extensive permissions.', $default_role ),
				'high',
				8.8,
				'Change the default role to "subscriber" in Settings → General.'
			);
		}

		// Check for users with empty passwords.
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$empty_pw_users = $wpdb->get_results(
			"SELECT ID, user_login FROM {$wpdb->users} WHERE user_pass = '' OR user_pass = MD5('')" // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		);

		foreach ( $empty_pw_users as $user ) {
			$vulnerabilities[] = $this->build(
				'user-empty-password-' . $user->ID,
				sprintf( 'User with empty password: %s', $user->user_login ),
				sprintf( 'The user account "%s" has an empty password, allowing unrestricted access.', $user->user_login ),
				'critical',
				9.8,
				sprintf( 'Immediately set a strong password for the user "%s".', $user->user_login )
			);
		}

		// Check for duplicate email addresses.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$duplicate_emails = $wpdb->get_results(
			"SELECT user_email, COUNT(*) as cnt FROM {$wpdb->users} GROUP BY user_email HAVING cnt > 1" // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		);

		foreach ( $duplicate_emails as $row ) {
			$vulnerabilities[] = $this->build(
				'user-duplicate-email-' . md5( $row->user_email ),
				'Duplicate email address in user accounts',
				sprintf( 'The email address "%s" is used by more than one user account.', $row->user_email ),
				'low',
				2.7,
				'Ensure each user account has a unique email address.'
			);
		}

		return $vulnerabilities;
	}

	/**
	 * Build a vulnerability array.
	 *
	 * @param string $id             Unique ID.
	 * @param string $title          Title.
	 * @param string $description    Description.
	 * @param string $severity       Severity level.
	 * @param float  $cvss           CVSS score.
	 * @param string $recommendation Recommendation.
	 * @return array
	 */
	private function build( $id, $title, $description, $severity, $cvss, $recommendation ) {
		return array(
			'component_type'    => 'user',
			'component_name'    => 'User Audit',
			'component_version' => '',
			'vulnerability_id'  => $id,
			'title'             => $title,
			'description'       => $description,
			'severity'          => $severity,
			'cvss_score'        => $cvss,
			'cvss_vector'       => '',
			'recommendation'    => $recommendation,
			'reference_urls'    => wp_json_encode( array( 'https://wordpress.org/support/article/hardening-wordpress/#user-accounts' ) ),
		);
	}
}
