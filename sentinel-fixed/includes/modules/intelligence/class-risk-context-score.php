<?php
/**
 * Risk Context Score — Dynamic contextual risk scoring.
 *
 * @package WP_Sentinel_Security
 * @since   1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Risk_Context_Score
 */
class Risk_Context_Score {

	/**
	 * Calculate a contextual risk score for a vulnerability.
	 *
	 * @param array $vulnerability Vulnerability data array.
	 * @param array $context       Context data from Context_Analyzer.
	 * @param array $intelligence  Full intelligence data array.
	 * @return array Score result with base_score, context_multiplier, final_score, adjusted_severity, confidence, summary.
	 */
	public function calculate( $vulnerability, $context, $intelligence ) {
		$base_score = $this->get_base_score( $vulnerability );
		$multiplier = $context['risk_multiplier'] ?? 1.0;

		$final_score = $base_score * $multiplier;
		$final_score = max( 0.0, min( 10.0, $final_score ) );

		$adjusted_severity = $this->score_to_severity( $final_score );
		$confidence        = $this->calculate_confidence( $context, $intelligence );
		$summary           = $this->build_summary( $vulnerability, $context, $base_score, $final_score, $adjusted_severity );

		return array(
			'base_score'        => round( $base_score, 1 ),
			'context_multiplier' => round( $multiplier, 2 ),
			'final_score'       => round( $final_score, 1 ),
			'adjusted_severity' => $adjusted_severity,
			'confidence'        => $confidence,
			'summary'           => $summary,
		);
	}

	/**
	 * Get base CVSS score or estimate from severity.
	 *
	 * @param array $vulnerability Vulnerability data.
	 * @return float
	 */
	private function get_base_score( $vulnerability ) {
		if ( ! empty( $vulnerability['cvss_score'] ) && is_numeric( $vulnerability['cvss_score'] ) ) {
			return (float) $vulnerability['cvss_score'];
		}
		return $this->severity_to_score( $vulnerability['severity'] ?? 'info' );
	}

	/**
	 * Map severity label to numeric score.
	 *
	 * @param string $severity Severity string.
	 * @return float
	 */
	public function severity_to_score( $severity ) {
		$map = array(
			'critical' => 9.5,
			'high'     => 7.5,
			'medium'   => 5.0,
			'low'      => 2.5,
			'info'     => 0.5,
		);
		return $map[ strtolower( $severity ) ] ?? 0.5;
	}

	/**
	 * Map numeric score to severity label.
	 *
	 * @param float $score Numeric score (0-10).
	 * @return string
	 */
	public function score_to_severity( $score ) {
		if ( $score >= 9.0 ) {
			return 'critical';
		}
		if ( $score >= 7.0 ) {
			return 'high';
		}
		if ( $score >= 4.0 ) {
			return 'medium';
		}
		if ( $score > 0.0 ) {
			return 'low';
		}
		return 'info';
	}

	/**
	 * Calculate confidence level (0-100) based on available data points.
	 *
	 * @param array $context     Context data.
	 * @param array $intelligence Intelligence data.
	 * @return int Confidence percentage.
	 */
	public function calculate_confidence( $context, $intelligence ) {
		$score = 50;

		// Add points for each verified context data point.
		if ( isset( $context['is_component_active'] ) ) {
			$score += 10;
		}
		if ( isset( $context['is_functionality_used'] ) ) {
			$score += 5;
		}
		if ( isset( $context['is_publicly_exposed'] ) ) {
			$score += 10;
		}
		if ( isset( $context['requires_authentication'] ) ) {
			$score += 5;
		}
		if ( isset( $context['has_known_exploit'] ) ) {
			$score += 10;
		}
		if ( isset( $context['is_behind_waf'] ) ) {
			$score += 5;
		}

		// Add points for available environment data.
		if ( ! empty( $intelligence['environment'] ) ) {
			$score += 5;
		}

		return min( 100, $score );
	}

	/**
	 * Build a human-readable summary of the score calculation.
	 *
	 * @param array  $vulnerability     Vulnerability data.
	 * @param array  $context           Context data.
	 * @param float  $base_score        Original base score.
	 * @param float  $final_score       Calculated final score.
	 * @param string $adjusted_severity Adjusted severity label.
	 * @return string
	 */
	private function build_summary( $vulnerability, $context, $base_score, $final_score, $adjusted_severity ) {
		$original_severity = $vulnerability['severity'] ?? 'info';
		$parts             = array();

		if ( ! empty( $context['mitigating_factors'] ) ) {
			$parts[] = sprintf(
				/* translators: %s: list of mitigating factors */
				__( 'Mitigating: %s', 'wp-sentinel-security' ),
				implode( ', ', $context['mitigating_factors'] )
			);
		}

		if ( ! empty( $context['aggravating_factors'] ) ) {
			$parts[] = sprintf(
				/* translators: %s: list of aggravating factors */
				__( 'Aggravating: %s', 'wp-sentinel-security' ),
				implode( ', ', $context['aggravating_factors'] )
			);
		}

		$direction = '';
		if ( $final_score < $base_score ) {
			$direction = __( 'Risk reduced', 'wp-sentinel-security' );
		} elseif ( $final_score > $base_score ) {
			$direction = __( 'Risk elevated', 'wp-sentinel-security' );
		} else {
			$direction = __( 'Risk unchanged', 'wp-sentinel-security' );
		}

		$summary = sprintf(
			/* translators: 1: direction phrase 2: original severity 3: adjusted severity 4: base score 5: final score */
			__( '%1$s from %2$s to %3$s (base %.1f → adjusted %.1f).', 'wp-sentinel-security' ),
			$direction,
			$original_severity,
			$adjusted_severity,
			$base_score,
			$final_score
		);

		if ( $parts ) {
			$summary .= ' ' . implode( '. ', $parts ) . '.';
		}

		return $summary;
	}
}
