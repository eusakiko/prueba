<?php
/**
 * Scoring Engine class.
 *
 * Calculates the overall security risk score and letter grade for the site.
 *
 * @package WP_Sentinel_Security
 * @since   1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Scoring_Engine
 */
class Scoring_Engine {

	/**
	 * Calculate the overall site security score.
	 *
	 * @return array Score data including grade, label, color, and breakdown.
	 */
	public static function calculate_site_score() {
		global $wpdb;

		// Fetch open vulnerabilities grouped by severity.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$severity_counts = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT severity, COUNT(*) as cnt FROM {$wpdb->prefix}sentinel_vulnerabilities WHERE status = %s GROUP BY severity",
				'open'
			),
			OBJECT_K
		);

		if ( $wpdb->last_error ) {
			$severity_counts = array();
		}

		$by_severity = array(
			'critical' => isset( $severity_counts['critical'] ) ? (int) $severity_counts['critical']->cnt : 0,
			'high'     => isset( $severity_counts['high'] ) ? (int) $severity_counts['high']->cnt : 0,
			'medium'   => isset( $severity_counts['medium'] ) ? (int) $severity_counts['medium']->cnt : 0,
			'low'      => isset( $severity_counts['low'] ) ? (int) $severity_counts['low']->cnt : 0,
			'info'     => isset( $severity_counts['info'] ) ? (int) $severity_counts['info']->cnt : 0,
		);

		// Calculate score penalties.
		$score = 100;
		$score -= $by_severity['critical'] * 20;
		$score -= $by_severity['high'] * 12;
		$score -= $by_severity['medium'] * 6;
		$score -= $by_severity['low'] * 2;

		// Hardening bonus.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$hardening_total = (int) $wpdb->get_var(
			"SELECT COUNT(*) FROM {$wpdb->prefix}sentinel_hardening_status" // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		);

		if ( $wpdb->last_error ) {
			$hardening_total = 0;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$hardening_applied = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->prefix}sentinel_hardening_status WHERE status = %s",
				'pass'
			)
		);

		if ( $wpdb->last_error ) {
			$hardening_applied = 0;
		}

		$hardening_ratio = $hardening_total > 0 ? $hardening_applied / $hardening_total : 0;
		$score          += (int) round( $hardening_ratio * 15 );

		// Clamp score to 0-100.
		$score = max( 0, min( 100, $score ) );

		$total_vulnerabilities = array_sum( $by_severity );
		$grade_data            = self::score_to_grade( $score );

		return array(
			'score'                  => $score,
			'grade'                  => $grade_data['grade'],
			'grade_label'            => $grade_data['label'],
			'grade_color'            => $grade_data['color'],
			'total_vulnerabilities'  => $total_vulnerabilities,
			'by_severity'            => $by_severity,
			'hardening_applied'      => $hardening_applied,
			'hardening_total'        => $hardening_total,
			'hardening_percentage'   => $hardening_total > 0 ? round( ( $hardening_applied / $hardening_total ) * 100 ) : 0,
		);
	}

	/**
	 * Convert a numeric score to a letter grade with label and color.
	 *
	 * @param int $score Numeric score (0-100).
	 * @return array {grade: string, label: string, color: string}
	 */
	public static function score_to_grade( $score ) {
		if ( $score >= 90 ) {
			return array( 'grade' => 'A+', 'label' => __( 'Excellent', 'wp-sentinel-security' ), 'color' => '#22c55e' );
		} elseif ( $score >= 80 ) {
			return array( 'grade' => 'A', 'label' => __( 'Very Good', 'wp-sentinel-security' ), 'color' => '#4ade80' );
		} elseif ( $score >= 70 ) {
			return array( 'grade' => 'B', 'label' => __( 'Good', 'wp-sentinel-security' ), 'color' => '#a3e635' );
		} elseif ( $score >= 60 ) {
			return array( 'grade' => 'C', 'label' => __( 'Fair', 'wp-sentinel-security' ), 'color' => '#facc15' );
		} elseif ( $score >= 50 ) {
			return array( 'grade' => 'D', 'label' => __( 'Poor', 'wp-sentinel-security' ), 'color' => '#fb923c' );
		} elseif ( $score >= 30 ) {
			return array( 'grade' => 'E', 'label' => __( 'Bad', 'wp-sentinel-security' ), 'color' => '#f87171' );
		} else {
			return array( 'grade' => 'F', 'label' => __( 'Critical Risk', 'wp-sentinel-security' ), 'color' => '#dc2626' );
		}
	}

	/**
	 * Get the overall risk level label and color for a given score.
	 *
	 * Maps a numeric security score to a human-readable risk level.
	 *
	 * @param int $score Numeric score (0-100).
	 * @return array {level: string, label: string, color: string}
	 */
	public static function get_risk_level( $score ) {
		if ( $score >= 70 ) {
			return array( 'level' => 'low',      'label' => __( 'Low',      'wp-sentinel-security' ), 'color' => '#16a34a' );
		} elseif ( $score >= 50 ) {
			return array( 'level' => 'medium',   'label' => __( 'Medium',   'wp-sentinel-security' ), 'color' => '#ca8a04' );
		} elseif ( $score >= 30 ) {
			return array( 'level' => 'high',     'label' => __( 'High',     'wp-sentinel-security' ), 'color' => '#ea580c' );
		} else {
			return array( 'level' => 'critical', 'label' => __( 'Critical', 'wp-sentinel-security' ), 'color' => '#dc2626' );
		}
	}

	/**
	 * Generate up to 3 top recommended actions from current score data.
	 *
	 * Rules are evaluated in priority order; the first three matched are
	 * returned. Each item contains display text, a sentinel admin page slug,
	 * and a call-to-action label.
	 *
	 * @param array $score    Score array returned by calculate_site_score().
	 * @param bool  $has_scan Whether at least one scan has completed.
	 * @return array[] Each element: {text: string, page: string, cta: string}
	 */
	public static function get_top_recommendations( array $score, $has_scan = true ) {
		$recs = array();

		if ( ! $has_scan ) {
			$recs[] = array(
				'text' => __( 'Run your first security scan to discover vulnerabilities.', 'wp-sentinel-security' ),
				'page' => 'sentinel-scanner',
				'cta'  => __( 'Go to Scanner', 'wp-sentinel-security' ),
			);
		}

		if ( $score['by_severity']['critical'] > 0 ) {
			$recs[] = array(
				/* translators: %d: number of critical vulnerabilities */
				'text' => sprintf(
					_n(
						'Fix %d critical vulnerability immediately to prevent a breach.',
						'Fix %d critical vulnerabilities immediately to prevent a breach.',
						$score['by_severity']['critical'],
						'wp-sentinel-security'
					),
					$score['by_severity']['critical']
				),
				'page' => 'sentinel-scanner',
				'cta'  => __( 'View Findings', 'wp-sentinel-security' ),
			);
		}

		if ( $score['by_severity']['high'] > 0 ) {
			$recs[] = array(
				/* translators: %d: number of high-severity vulnerabilities */
				'text' => sprintf(
					_n(
						'Address %d high-severity vulnerability within 48 hours.',
						'Address %d high-severity vulnerabilities within 48 hours.',
						$score['by_severity']['high'],
						'wp-sentinel-security'
					),
					$score['by_severity']['high']
				),
				'page' => 'sentinel-scanner',
				'cta'  => __( 'View Findings', 'wp-sentinel-security' ),
			);
		}

		if ( count( $recs ) < 3 && $score['hardening_percentage'] < 50 ) {
			$recs[] = array(
				'text' => __( 'Apply hardening measures to strengthen your security posture.', 'wp-sentinel-security' ),
				'page' => 'sentinel-hardening',
				'cta'  => __( 'Go to Hardening', 'wp-sentinel-security' ),
			);
		}

		if ( count( $recs ) < 3 && $score['by_severity']['medium'] > 0 ) {
			$recs[] = array(
				/* translators: %d: number of medium-severity vulnerabilities */
				'text' => sprintf(
					_n(
						'Review %d medium-severity vulnerability this week.',
						'Review %d medium-severity vulnerabilities this week.',
						$score['by_severity']['medium'],
						'wp-sentinel-security'
					),
					$score['by_severity']['medium']
				),
				'page' => 'sentinel-scanner',
				'cta'  => __( 'View Findings', 'wp-sentinel-security' ),
			);
		}

		if ( empty( $recs ) ) {
			$recs[] = array(
				'text' => __( 'Your site is well-secured. Keep monitoring with regular scans.', 'wp-sentinel-security' ),
				'page' => 'sentinel-scanner',
				'cta'  => __( 'Run Scan', 'wp-sentinel-security' ),
			);
		}

		return array_slice( $recs, 0, 3 );
	}

	/**
	 * Get score history averaged per day over the past N days.
	 *
	 * @param int $days Number of days of history to retrieve.
	 * @return array Array of {date, avg_score} objects.
	 */
	public static function get_score_history( $days = 30 ) {
		global $wpdb;

		// Use WordPress-timezone-aware cutoff instead of raw DATE_SUB(NOW()).
		$cutoff = gmdate( 'Y-m-d H:i:s', current_time( 'timestamp' ) - absint( $days ) * DAY_IN_SECONDS );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT
				    DATE(completed_at)        AS date,
				    ROUND(AVG(risk_score), 1) AS avg_score,
				    MAX(risk_score)           AS max_score,
				    MIN(risk_score)           AS min_score,
				    SUM(vulnerabilities_found) AS total_vulns,
				    COUNT(*)                  AS scan_count
				FROM {$wpdb->prefix}sentinel_scans
				WHERE status     = %s
				  AND completed_at >= %s
				GROUP BY DATE(completed_at)
				ORDER BY date ASC",
				'completed',
				$cutoff
			)
		);
	}
}
