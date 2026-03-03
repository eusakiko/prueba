<?php
/**
 * HTML report renderer.
 *
 * Produces standalone, print-ready HTML strings for technical, executive,
 * and compliance reports. All output is properly escaped.
 *
 * @package WP_Sentinel_Security
 * @since   2.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Report_HTML_Renderer
 */
class Report_HTML_Renderer {

	/**
	 * Inline CSS shared by all report types.
	 *
	 * @return string
	 */
	private function base_styles() {
		return '
		* { box-sizing: border-box; margin: 0; padding: 0; }
		body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; font-size: 13px; color: #1e293b; background: #f8fafc; }
		a { color: #4f46e5; text-decoration: none; }
		h1, h2, h3, h4 { color: #0f172a; }
		.report-wrap { max-width: 1100px; margin: 0 auto; padding: 32px 16px; }
		/* Cover */
		.cover { background: linear-gradient(135deg, #1e293b 0%, #334155 100%); color: #fff; border-radius: 10px; padding: 60px 48px; margin-bottom: 32px; }
		.cover h1 { font-size: 32px; font-weight: 700; margin-bottom: 8px; }
		.cover .meta { opacity: .75; font-size: 13px; margin-top: 16px; line-height: 1.8; }
		/* Cards */
		.card { background: #fff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 24px; margin-bottom: 24px; }
		.card h2 { font-size: 18px; font-weight: 600; border-bottom: 2px solid #e2e8f0; padding-bottom: 10px; margin-bottom: 16px; }
		.card h3 { font-size: 15px; font-weight: 600; margin-bottom: 8px; }
		/* Metrics grid */
		.metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 16px; margin-bottom: 24px; }
		.metric { background: #f1f5f9; border-radius: 8px; padding: 16px; text-align: center; }
		.metric .value { font-size: 36px; font-weight: 700; }
		.metric .label { font-size: 12px; color: #64748b; margin-top: 4px; }
		.metric.critical .value { color: #dc2626; }
		.metric.high .value { color: #ea580c; }
		.metric.medium .value { color: #ca8a04; }
		.metric.low .value { color: #16a34a; }
		.metric.info .value { color: #2563eb; }
		/* Badges */
		.badge { display: inline-block; padding: 2px 10px; border-radius: 99px; font-size: 11px; font-weight: 600; text-transform: uppercase; }
		.badge-critical { background: #fef2f2; color: #dc2626; }
		.badge-high { background: #fff7ed; color: #ea580c; }
		.badge-medium { background: #fefce8; color: #ca8a04; }
		.badge-low { background: #f0fdf4; color: #16a34a; }
		.badge-info { background: #eff6ff; color: #2563eb; }
		.badge-pass { background: #f0fdf4; color: #16a34a; }
		.badge-fail { background: #fef2f2; color: #dc2626; }
		/* Tables */
		table { width: 100%; border-collapse: collapse; font-size: 12px; }
		th { background: #f8fafc; color: #475569; font-weight: 600; padding: 10px 12px; text-align: left; border-bottom: 2px solid #e2e8f0; }
		td { padding: 9px 12px; border-bottom: 1px solid #f1f5f9; vertical-align: top; }
		tr:last-child td { border-bottom: none; }
		/* Recommendations */
		.rec-item { background: #f8fafc; border-left: 4px solid #4f46e5; border-radius: 4px; padding: 12px 16px; margin-bottom: 12px; }
		.rec-item h4 { font-size: 13px; color: #4f46e5; margin-bottom: 4px; }
		/* Footer */
		.report-footer { text-align: center; color: #94a3b8; font-size: 11px; margin-top: 32px; padding-top: 16px; border-top: 1px solid #e2e8f0; }
		/* Print */
		@media print {
			body { background: #fff; }
			.cover { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
			.card { border: 1px solid #ccc; page-break-inside: avoid; }
			.badge { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
		}
		';
	}

	/**
	 * Wrap rendered body HTML in a full standalone HTML document.
	 *
	 * @param string $title  Report title.
	 * @param string $body   Inner HTML content.
	 * @return string Full HTML document.
	 */
	private function wrap_html( $title, $body ) {
		$lang = str_replace( '_', '-', get_locale() );
		return '<!DOCTYPE html>
<html lang="' . esc_attr( $lang ) . '">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>' . esc_html( $title ) . '</title>
<style>' . $this->base_styles() . '</style>
</head>
<body>
<div class="report-wrap">' . $body . '</div>
</body>
</html>';
	}

	/**
	 * Get a severity badge HTML string.
	 *
	 * @param string $severity Severity level.
	 * @return string Badge HTML.
	 */
	private function severity_badge( $severity ) {
		$sev = strtolower( sanitize_text_field( $severity ) );
		return '<span class="badge badge-' . esc_attr( $sev ) . '">' . esc_html( ucfirst( $sev ) ) . '</span>';
	}

	/**
	 * Render a full technical HTML report.
	 *
	 * @param array $data {
	 *     Report data.
	 *
	 *     @type array  $metadata          generated_at, report_type, site_url, company_name, schema_version
	 *     @type array  $vulnerabilities   Vulnerability objects or arrays.
	 *     @type array  $hardening_checks  Hardening check objects or arrays.
	 *     @type array  $settings          company_name, company_logo
	 * }
	 * @return string Standalone HTML document.
	 */
	public function render_technical( $data ) {
		$metadata  = isset( $data['metadata'] ) ? $data['metadata'] : array();
		$vulns     = isset( $data['vulnerabilities'] ) ? $data['vulnerabilities'] : array();
		$hardening = isset( $data['hardening_checks'] ) ? $data['hardening_checks'] : array();
		$settings  = isset( $data['settings'] ) ? $data['settings'] : array();

		$company   = esc_html( $settings['company_name'] ?? $metadata['company_name'] ?? '' );
		$site_url  = esc_url( $metadata['site_url'] ?? get_site_url() );
		$gen_at    = esc_html( $metadata['generated_at'] ?? current_time( 'Y-m-d H:i:s' ) );

		$vuln_count    = count( $vulns );
		$critical      = 0; $high = 0; $medium = 0; $low = 0;
		foreach ( $vulns as $v ) {
			$sev = strtolower( (string) ( is_array( $v ) ? $v['severity'] : $v->severity ) );
			if ( 'critical' === $sev ) { $critical++; }
			elseif ( 'high' === $sev ) { $high++; }
			elseif ( 'medium' === $sev ) { $medium++; }
			else { $low++; }
		}

		ob_start();
		?>
<!-- Cover -->
<div class="cover">
	<h1><?php echo esc_html__( 'Security Report — Technical', 'wp-sentinel-security' ); ?></h1>
	<?php if ( $company ) : ?>
	<div style="font-size:18px;font-weight:600;margin-top:8px;"><?php echo $company; // Already escaped. ?></div>
	<?php endif; ?>
	<div class="meta">
		<?php esc_html_e( 'Site:', 'wp-sentinel-security' ); ?> <?php echo $site_url; // Already escaped. ?><br>
		<?php esc_html_e( 'Generated:', 'wp-sentinel-security' ); ?> <?php echo $gen_at; // Already escaped. ?><br>
		<?php esc_html_e( 'Schema Version:', 'wp-sentinel-security' ); ?> <?php echo esc_html( $metadata['schema_version'] ?? '2.0.0' ); ?>
	</div>
</div>

<!-- Executive Summary -->
<div class="card">
	<h2><?php esc_html_e( 'Executive Summary', 'wp-sentinel-security' ); ?></h2>
	<div class="metrics">
		<div class="metric critical">
			<div class="value"><?php echo esc_html( $critical ); ?></div>
			<div class="label"><?php esc_html_e( 'Critical', 'wp-sentinel-security' ); ?></div>
		</div>
		<div class="metric high">
			<div class="value"><?php echo esc_html( $high ); ?></div>
			<div class="label"><?php esc_html_e( 'High', 'wp-sentinel-security' ); ?></div>
		</div>
		<div class="metric medium">
			<div class="value"><?php echo esc_html( $medium ); ?></div>
			<div class="label"><?php esc_html_e( 'Medium', 'wp-sentinel-security' ); ?></div>
		</div>
		<div class="metric low">
			<div class="value"><?php echo esc_html( $low ); ?></div>
			<div class="label"><?php esc_html_e( 'Low', 'wp-sentinel-security' ); ?></div>
		</div>
		<div class="metric">
			<div class="value"><?php echo esc_html( $vuln_count ); ?></div>
			<div class="label"><?php esc_html_e( 'Total', 'wp-sentinel-security' ); ?></div>
		</div>
	</div>
</div>

<!-- Vulnerability Details -->
<div class="card">
	<h2><?php esc_html_e( 'Vulnerability Details', 'wp-sentinel-security' ); ?></h2>
	<?php if ( $vulns ) : ?>
	<table>
		<thead>
			<tr>
				<th><?php esc_html_e( 'Component', 'wp-sentinel-security' ); ?></th>
				<th><?php esc_html_e( 'Vulnerability', 'wp-sentinel-security' ); ?></th>
				<th><?php esc_html_e( 'CVE', 'wp-sentinel-security' ); ?></th>
				<th><?php esc_html_e( 'Severity', 'wp-sentinel-security' ); ?></th>
				<th><?php esc_html_e( 'CVSS', 'wp-sentinel-security' ); ?></th>
				<th><?php esc_html_e( 'Status', 'wp-sentinel-security' ); ?></th>
				<th><?php esc_html_e( 'Detected', 'wp-sentinel-security' ); ?></th>
			</tr>
		</thead>
		<tbody>
		<?php foreach ( $vulns as $v ) :
			$v = (array) $v;
			// Build CVE link if available.
			$cve_html = '—';
			if ( ! empty( $v['vulnerability_id'] ) && preg_match( '/^CVE-\d{4}-\d+$/i', $v['vulnerability_id'] ) ) {
				$cve_id   = esc_html( strtoupper( $v['vulnerability_id'] ) );
				$cve_url  = 'https://nvd.nist.gov/vuln/detail/' . esc_attr( $v['vulnerability_id'] );
				$cve_html = '<a href="' . $cve_url . '" style="color:#4f46e5;font-weight:600;" target="_blank">' . $cve_id . ' ↗</a>';
			}
			?>
			<tr>
				<td>
					<?php echo esc_html( $v['component_name'] ?? '' ); ?>
					<br><small style="color:#64748b"><?php echo esc_html( $v['component_version'] ?? '' ); ?></small>
				</td>
				<td>
					<strong><?php echo esc_html( $v['title'] ?? '' ); ?></strong>
					<?php if ( ! empty( $v['description'] ) ) : ?>
					<br><small><?php echo esc_html( wp_trim_words( $v['description'], 20 ) ); ?></small>
					<?php endif; ?>
				</td>
				<td><?php echo $cve_html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?></td>
				<td><?php echo $this->severity_badge( $v['severity'] ?? 'info' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?></td>
				<td><?php echo esc_html( $v['cvss_score'] ?? '—' ); ?></td>
				<td><?php echo esc_html( ucfirst( $v['status'] ?? '' ) ); ?></td>
				<td><?php echo esc_html( $v['detected_at'] ?? '' ); ?></td>
			</tr>
		<?php endforeach; ?>
		</tbody>
	</table>
	<?php else : ?>
	<p><?php esc_html_e( 'No vulnerabilities found.', 'wp-sentinel-security' ); ?></p>
	<?php endif; ?>
</div>

<!-- Recommendations -->
<?php if ( $vulns ) : ?>
<div class="card">
	<h2><?php esc_html_e( 'Recommendations', 'wp-sentinel-security' ); ?></h2>
	<?php foreach ( $vulns as $v ) :
		$v = (array) $v;
		if ( empty( $v['recommendation'] ) ) { continue; }
		?>
	<div class="rec-item">
		<h4><?php echo esc_html( $v['component_name'] ?? '' ); ?> — <?php echo esc_html( $v['title'] ?? '' ); ?></h4>
		<p><?php echo esc_html( $v['recommendation'] ); ?></p>
	</div>
	<?php endforeach; ?>
</div>
<?php endif; ?>

<!-- Appendix: Hardening Status -->
<?php if ( $hardening ) : ?>
<div class="card">
	<h2><?php esc_html_e( 'Appendix — Hardening Status', 'wp-sentinel-security' ); ?></h2>
	<table>
		<thead>
			<tr>
				<th><?php esc_html_e( 'Check', 'wp-sentinel-security' ); ?></th>
				<th><?php esc_html_e( 'Category', 'wp-sentinel-security' ); ?></th>
				<th><?php esc_html_e( 'Status', 'wp-sentinel-security' ); ?></th>
			</tr>
		</thead>
		<tbody>
		<?php foreach ( $hardening as $c ) :
			$c      = (array) $c;
			$status = strtolower( $c['status'] ?? 'fail' );
			?>
			<tr>
				<td><?php echo esc_html( $c['name'] ?? $c['check_name'] ?? '' ); ?></td>
				<td><?php echo esc_html( $c['category'] ?? '' ); ?></td>
				<td><span class="badge badge-<?php echo esc_attr( 'pass' === $status ? 'pass' : 'fail' ); ?>"><?php echo esc_html( ucfirst( $status ) ); ?></span></td>
			</tr>
		<?php endforeach; ?>
		</tbody>
	</table>
</div>
<?php endif; ?>

<div class="report-footer">
	<?php
	printf(
		/* translators: %s: Site URL */
		esc_html__( 'Generated by WP Sentinel Security — %s', 'wp-sentinel-security' ),
		esc_html( get_site_url() )
	);
	?>
</div>
		<?php
		$body = ob_get_clean();
		return $this->wrap_html( __( 'Technical Security Report', 'wp-sentinel-security' ), $body );
	}

	/**
	 * Render an executive summary HTML report.
	 *
	 * @param array $data {
	 *     @type array $metadata         generated_at, site_url, company_name
	 *     @type array $vulnerabilities  Vulnerability objects or arrays.
	 *     @type array $scan_results     Summary stats array.
	 *     @type array $settings         company_name, company_logo
	 * }
	 * @return string Standalone HTML document.
	 */
	public function render_executive( $data ) {
		$metadata  = isset( $data['metadata'] ) ? $data['metadata'] : array();
		$vulns     = isset( $data['vulnerabilities'] ) ? $data['vulnerabilities'] : array();
		$scan      = isset( $data['scan_results'] ) ? $data['scan_results'] : array();
		$settings  = isset( $data['settings'] ) ? $data['settings'] : array();

		$company  = esc_html( $settings['company_name'] ?? $metadata['company_name'] ?? '' );
		$site_url = esc_url( $metadata['site_url'] ?? get_site_url() );
		$gen_at   = esc_html( $metadata['generated_at'] ?? current_time( 'Y-m-d H:i:s' ) );

		$by_sev = array( 'critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0 );
		foreach ( $vulns as $v ) {
			$sev = strtolower( (string) ( is_array( $v ) ? ( $v['severity'] ?? 'info' ) : ( $v->severity ?? 'info' ) ) );
			if ( isset( $by_sev[ $sev ] ) ) {
				$by_sev[ $sev ]++;
			}
		}

		$risk_score = isset( $scan['risk_score'] ) ? (int) $scan['risk_score'] : 0;

		ob_start();
		?>
<div class="cover">
	<h1><?php esc_html_e( 'Executive Security Summary', 'wp-sentinel-security' ); ?></h1>
	<?php if ( $company ) : ?>
	<div style="font-size:18px;font-weight:600;margin-top:8px;"><?php echo $company; // Already escaped. ?></div>
	<?php endif; ?>
	<div class="meta">
		<?php esc_html_e( 'Site:', 'wp-sentinel-security' ); ?> <?php echo $site_url; // Already escaped. ?><br>
		<?php esc_html_e( 'Generated:', 'wp-sentinel-security' ); ?> <?php echo $gen_at; // Already escaped. ?>
	</div>
</div>

<div class="card">
	<h2><?php esc_html_e( 'Risk Overview', 'wp-sentinel-security' ); ?></h2>
	<div class="metrics">
		<div class="metric">
			<div class="value"><?php echo esc_html( $risk_score ); ?></div>
			<div class="label"><?php esc_html_e( 'Risk Score', 'wp-sentinel-security' ); ?></div>
		</div>
		<?php foreach ( $by_sev as $sev => $cnt ) : ?>
		<div class="metric <?php echo esc_attr( $sev ); ?>">
			<div class="value"><?php echo esc_html( $cnt ); ?></div>
			<div class="label"><?php echo esc_html( ucfirst( $sev ) ); ?></div>
		</div>
		<?php endforeach; ?>
	</div>
</div>

<div class="card">
	<h2><?php esc_html_e( 'Top Findings', 'wp-sentinel-security' ); ?></h2>
	<?php
	$top = array_slice( $vulns, 0, 10 );
	if ( $top ) :
	?>
	<table>
		<thead>
			<tr>
				<th><?php esc_html_e( 'Component', 'wp-sentinel-security' ); ?></th>
				<th><?php esc_html_e( 'Vulnerability', 'wp-sentinel-security' ); ?></th>
				<th><?php esc_html_e( 'Severity', 'wp-sentinel-security' ); ?></th>
				<th><?php esc_html_e( 'CVSS', 'wp-sentinel-security' ); ?></th>
			</tr>
		</thead>
		<tbody>
		<?php foreach ( $top as $v ) :
			$v = (array) $v; ?>
			<tr>
				<td><?php echo esc_html( $v['component_name'] ?? '' ); ?></td>
				<td><?php echo esc_html( $v['title'] ?? '' ); ?></td>
				<td><?php echo $this->severity_badge( $v['severity'] ?? 'info' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?></td>
				<td><?php echo esc_html( $v['cvss_score'] ?? '—' ); ?></td>
			</tr>
		<?php endforeach; ?>
		</tbody>
	</table>
	<?php else : ?>
	<p><?php esc_html_e( 'No significant findings.', 'wp-sentinel-security' ); ?></p>
	<?php endif; ?>
</div>

<div class="report-footer">
	<?php
	printf(
		/* translators: %s: Site URL */
		esc_html__( 'Generated by WP Sentinel Security — %s', 'wp-sentinel-security' ),
		esc_html( get_site_url() )
	);
	?>
</div>
		<?php
		$body = ob_get_clean();
		return $this->wrap_html( __( 'Executive Security Summary', 'wp-sentinel-security' ), $body );
	}

	/**
	 * Render a compliance-style HTML report.
	 *
	 * @param array $data {
	 *     @type array $metadata        generated_at, site_url, company_name
	 *     @type array $hardening_checks Hardening check objects or arrays.
	 *     @type array $settings        company_name
	 * }
	 * @return string Standalone HTML document.
	 */
	public function render_compliance( $data ) {
		$metadata  = isset( $data['metadata'] ) ? $data['metadata'] : array();
		$checks    = isset( $data['hardening_checks'] ) ? $data['hardening_checks'] : array();
		$settings  = isset( $data['settings'] ) ? $data['settings'] : array();

		$company  = esc_html( $settings['company_name'] ?? $metadata['company_name'] ?? '' );
		$site_url = esc_url( $metadata['site_url'] ?? get_site_url() );
		$gen_at   = esc_html( $metadata['generated_at'] ?? current_time( 'Y-m-d H:i:s' ) );

		$pass = 0; $fail = 0;
		foreach ( $checks as $c ) {
			$c = (array) $c;
			if ( 'pass' === strtolower( $c['status'] ?? '' ) ) {
				$pass++;
			} else {
				$fail++;
			}
		}
		$total  = $pass + $fail;
		$pct    = $total > 0 ? round( ( $pass / $total ) * 100 ) : 0;

		ob_start();
		?>
<div class="cover">
	<h1><?php esc_html_e( 'Compliance Report', 'wp-sentinel-security' ); ?></h1>
	<?php if ( $company ) : ?>
	<div style="font-size:18px;font-weight:600;margin-top:8px;"><?php echo $company; // Already escaped. ?></div>
	<?php endif; ?>
	<div class="meta">
		<?php esc_html_e( 'Site:', 'wp-sentinel-security' ); ?> <?php echo $site_url; // Already escaped. ?><br>
		<?php esc_html_e( 'Generated:', 'wp-sentinel-security' ); ?> <?php echo $gen_at; // Already escaped. ?>
	</div>
</div>

<div class="card">
	<h2><?php esc_html_e( 'Compliance Overview', 'wp-sentinel-security' ); ?></h2>
	<div class="metrics">
		<div class="metric">
			<div class="value"><?php echo esc_html( $pct ); ?>%</div>
			<div class="label"><?php esc_html_e( 'Compliance', 'wp-sentinel-security' ); ?></div>
		</div>
		<div class="metric low">
			<div class="value"><?php echo esc_html( $pass ); ?></div>
			<div class="label"><?php esc_html_e( 'Pass', 'wp-sentinel-security' ); ?></div>
		</div>
		<div class="metric critical">
			<div class="value"><?php echo esc_html( $fail ); ?></div>
			<div class="label"><?php esc_html_e( 'Fail', 'wp-sentinel-security' ); ?></div>
		</div>
		<div class="metric">
			<div class="value"><?php echo esc_html( $total ); ?></div>
			<div class="label"><?php esc_html_e( 'Total', 'wp-sentinel-security' ); ?></div>
		</div>
	</div>
</div>

<div class="card">
	<h2><?php esc_html_e( 'Check Results', 'wp-sentinel-security' ); ?></h2>
	<?php if ( $checks ) : ?>
	<table>
		<thead>
			<tr>
				<th><?php esc_html_e( 'Check', 'wp-sentinel-security' ); ?></th>
				<th><?php esc_html_e( 'Category', 'wp-sentinel-security' ); ?></th>
				<th><?php esc_html_e( 'Risk Level', 'wp-sentinel-security' ); ?></th>
				<th><?php esc_html_e( 'Status', 'wp-sentinel-security' ); ?></th>
				<th><?php esc_html_e( 'Description', 'wp-sentinel-security' ); ?></th>
			</tr>
		</thead>
		<tbody>
		<?php foreach ( $checks as $c ) :
			$c      = (array) $c;
			$status = strtolower( $c['status'] ?? 'fail' );
			?>
			<tr>
				<td><strong><?php echo esc_html( $c['name'] ?? $c['check_name'] ?? '' ); ?></strong></td>
				<td><?php echo esc_html( $c['category'] ?? '' ); ?></td>
				<td><?php echo $this->severity_badge( $c['risk_level'] ?? $c['severity'] ?? 'medium' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?></td>
				<td><span class="badge badge-<?php echo esc_attr( 'pass' === $status ? 'pass' : 'fail' ); ?>"><?php echo esc_html( ucfirst( $status ) ); ?></span></td>
				<td><?php echo esc_html( $c['description'] ?? '' ); ?></td>
			</tr>
		<?php endforeach; ?>
		</tbody>
	</table>
	<?php else : ?>
	<p><?php esc_html_e( 'No hardening checks found.', 'wp-sentinel-security' ); ?></p>
	<?php endif; ?>
</div>

<div class="report-footer">
	<?php
	printf(
		/* translators: %s: Site URL */
		esc_html__( 'Generated by WP Sentinel Security — %s', 'wp-sentinel-security' ),
		esc_html( get_site_url() )
	);
	?>
</div>
		<?php
		$body = ob_get_clean();
		return $this->wrap_html( __( 'Compliance Report', 'wp-sentinel-security' ), $body );
	}
}
