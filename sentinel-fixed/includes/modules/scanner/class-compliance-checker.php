<?php
/**
 * Compliance Checker — maps WordPress security state to OWASP Top 10 (2021),
 * PCI-DSS basics, and GDPR security requirements.
 *
 * @package WP_Sentinel_Security
 * @since   2.2.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Compliance_Checker
 */
class Compliance_Checker {

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
	 * Run all compliance checks.
	 *
	 * @return array Array of vulnerability data arrays.
	 */
	public function scan() {
		$vulnerabilities = array();

		$vulnerabilities = array_merge(
			$vulnerabilities,
			$this->check_owasp_top_10(),
			$this->check_pci_dss(),
			$this->check_gdpr()
		);

		return $vulnerabilities;
	}

	/**
	 * OWASP Top 10 (2021) checks.
	 *
	 * @return array
	 */
	private function check_owasp_top_10() {
		$vulnerabilities = array();

		// A01: Broken Access Control — check file editing is disabled.
		if ( ! defined( 'DISALLOW_FILE_EDIT' ) || ! DISALLOW_FILE_EDIT ) {
			$vulnerabilities[] = $this->make_finding(
				'owasp-a01-file-edit',
				'compliance',
				'OWASP A01 — Broken Access Control: File Editing Enabled',
				'WordPress file editor is enabled, allowing attackers with admin access to modify PHP files.',
				'Add define("DISALLOW_FILE_EDIT", true); to your wp-config.php.',
				'medium',
				5.5,
				'https://owasp.org/Top10/A01_2021-Broken_Access_Control/'
			);
		}

		// A02: Cryptographic Failures — check HTTPS.
		if ( ! is_ssl() ) {
			$vulnerabilities[] = $this->make_finding(
				'owasp-a02-no-ssl',
				'compliance',
				'OWASP A02 — Cryptographic Failures: Site Not Served Over HTTPS',
				'The site is not using HTTPS, exposing data in transit to eavesdropping.',
				'Install an SSL/TLS certificate and enforce HTTPS for all traffic.',
				'high',
				7.5,
				'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'
			);
		}

		// A05: Security Misconfiguration — WP_DEBUG in production.
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			$vulnerabilities[] = $this->make_finding(
				'owasp-a05-debug-enabled',
				'compliance',
				'OWASP A05 — Security Misconfiguration: WP_DEBUG Enabled',
				'WP_DEBUG is enabled, which can leak sensitive server information to visitors.',
				'Set define("WP_DEBUG", false); in your wp-config.php on production servers.',
				'medium',
				5.3,
				'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
			);
		}

		// A05: Default table prefix.
		global $wpdb;
		if ( isset( $wpdb->prefix ) && 'wp_' === $wpdb->prefix ) {
			$vulnerabilities[] = $this->make_finding(
				'owasp-a05-default-prefix',
				'compliance',
				'OWASP A05 — Security Misconfiguration: Default Database Table Prefix',
				'WordPress is using the default "wp_" table prefix, making SQL injection attacks easier.',
				'Change the database table prefix in wp-config.php and update the database tables.',
				'low',
				3.7,
				'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
			);
		}

		// A06: Vulnerable and Outdated Components — check WordPress version.
		global $wp_version;
		if ( isset( $wp_version ) ) {
			$latest = get_transient( 'sentinel_latest_wp_version' );
			if ( $latest && version_compare( $wp_version, $latest, '<' ) ) {
				$vulnerabilities[] = $this->make_finding(
					'owasp-a06-outdated-core',
					'compliance',
					'OWASP A06 — Vulnerable & Outdated Components: WordPress Core Outdated',
					sprintf( 'WordPress %s is installed; latest version is %s.', esc_html( $wp_version ), esc_html( $latest ) ),
					'Update WordPress to the latest version via Dashboard → Updates.',
					'high',
					7.5,
					'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/'
				);
			}
		}

		// A07: Identification and Authentication Failures — admin user "admin".
		if ( get_user_by( 'login', 'admin' ) ) {
			$vulnerabilities[] = $this->make_finding(
				'owasp-a07-admin-username',
				'compliance',
				'OWASP A07 — Authentication Failures: Default "admin" Username Exists',
				'A user with the username "admin" was found. This is a common target for brute-force attacks.',
				'Rename or delete the "admin" user account.',
				'medium',
				6.5,
				'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/'
			);
		}

		// A09: Security Logging — check if activity logging is configured.
		if ( empty( $this->settings['alert_channels'] ) ) {
			$vulnerabilities[] = $this->make_finding(
				'owasp-a09-no-alerts',
				'compliance',
				'OWASP A09 — Security Logging & Monitoring Failures: No Alert Channel Configured',
				'No alert channels are configured. Security events may go unnoticed.',
				'Configure at least one alert channel in Sentinel → Settings → Alerts.',
				'medium',
				5.0,
				'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/'
			);
		}

		return $vulnerabilities;
	}

	/**
	 * Basic PCI-DSS compliance checks for WordPress e-commerce sites.
	 *
	 * @return array
	 */
	private function check_pci_dss() {
		$vulnerabilities = array();

		// PCI-DSS 6.3: Use of strong cryptography.
		if ( ! is_ssl() ) {
			$vulnerabilities[] = $this->make_finding(
				'pci-dss-6.3-no-tls',
				'compliance',
				'PCI-DSS 6.3 — Strong Cryptography: HTTPS Not Enforced',
				'PCI-DSS requires all cardholder data environments to use strong cryptography (TLS 1.2+).',
				'Install a valid SSL/TLS certificate and enable the FORCE_SSL_ADMIN constant.',
				'high',
				8.0,
				'https://www.pcisecuritystandards.org/'
			);
		}

		// PCI-DSS 2.2: Do not use vendor-supplied defaults.
		global $wpdb;
		if ( isset( $wpdb->prefix ) && 'wp_' === $wpdb->prefix ) {
			$vulnerabilities[] = $this->make_finding(
				'pci-dss-2.2-default-prefix',
				'compliance',
				'PCI-DSS 2.2 — Vendor Defaults: Default Database Prefix',
				'PCI-DSS requires changing all vendor-supplied defaults including database credentials and prefixes.',
				'Change the wp_ database prefix to a unique value.',
				'medium',
				5.0,
				'https://www.pcisecuritystandards.org/'
			);
		}

		// PCI-DSS 8.2: Proper identification for all users.
		if ( get_user_by( 'login', 'admin' ) ) {
			$vulnerabilities[] = $this->make_finding(
				'pci-dss-8.2-admin-user',
				'compliance',
				'PCI-DSS 8.2 — User Identification: Generic Admin Account',
				'PCI-DSS 8.2 requires unique user IDs. A generic "admin" account violates this requirement.',
				'Replace the generic admin account with accounts named after specific individuals.',
				'medium',
				5.5,
				'https://www.pcisecuritystandards.org/'
			);
		}

		// PCI-DSS 6.5: Address common coding vulnerabilities.
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			$vulnerabilities[] = $this->make_finding(
				'pci-dss-6.5-debug',
				'compliance',
				'PCI-DSS 6.5 — Coding Vulnerabilities: Debug Mode Enabled',
				'Debug mode can expose sensitive information including database queries and file paths.',
				'Disable WP_DEBUG in production.',
				'high',
				7.0,
				'https://www.pcisecuritystandards.org/'
			);
		}

		return $vulnerabilities;
	}

	/**
	 * GDPR security requirement checks.
	 *
	 * @return array
	 */
	private function check_gdpr() {
		$vulnerabilities = array();

		// GDPR Art. 32: Encryption of personal data in transit.
		if ( ! is_ssl() ) {
			$vulnerabilities[] = $this->make_finding(
				'gdpr-art32-no-encryption',
				'compliance',
				'GDPR Art. 32 — Data Encryption: No HTTPS',
				'GDPR Article 32 requires appropriate technical measures including encryption of personal data. HTTPS is required.',
				'Implement HTTPS across the entire site using a valid SSL/TLS certificate.',
				'high',
				8.0,
				'https://gdpr-info.eu/art-32-gdpr/'
			);
		}

		// GDPR Art. 32: Access control to personal data.
		if ( ! defined( 'FORCE_SSL_ADMIN' ) || ! FORCE_SSL_ADMIN ) {
			$vulnerabilities[] = $this->make_finding(
				'gdpr-art32-ssl-admin',
				'compliance',
				'GDPR Art. 32 — Access Control: Admin Area Not Forced to HTTPS',
				'GDPR requires ensuring ongoing confidentiality of processing systems. Admin area should be HTTPS-only.',
				'Add define("FORCE_SSL_ADMIN", true); to your wp-config.php.',
				'medium',
				5.5,
				'https://gdpr-info.eu/art-32-gdpr/'
			);
		}

		// GDPR Art. 5: Data minimization — check log retention.
		$retention = $this->settings['log_retention_days'] ?? 90;
		if ( (int) $retention > 365 ) {
			$vulnerabilities[] = $this->make_finding(
				'gdpr-art5-log-retention',
				'compliance',
				'GDPR Art. 5 — Data Minimization: Excessive Log Retention',
				sprintf( 'Activity logs are retained for %d days. GDPR requires data minimization.', (int) $retention ),
				'Reduce log retention to 90 days or less in Sentinel → Settings.',
				'low',
				3.0,
				'https://gdpr-info.eu/art-5-gdpr/'
			);
		}

		return $vulnerabilities;
	}

	/**
	 * Build a compliance finding array.
	 *
	 * @param string $id          Unique finding identifier.
	 * @param string $type        Component type.
	 * @param string $title       Finding title.
	 * @param string $description Detailed description.
	 * @param string $recommendation Recommended fix.
	 * @param string $severity    critical|high|medium|low|info.
	 * @param float  $cvss_score  CVSS v3 score.
	 * @param string $reference   Reference URL.
	 * @return array
	 */
	private function make_finding( $id, $type, $title, $description, $recommendation, $severity, $cvss_score, $reference = '' ) {
		return array(
			'component_type'    => $type,
			'component_name'    => $id,
			'component_version' => '',
			'severity'          => $severity,
			'cvss_score'        => (float) $cvss_score,
			'title'             => $title,
			'description'       => $description,
			'recommendation'    => $recommendation,
			'reference'         => $reference,
		);
	}
}
