<?php
/**
 * Reports admin view.
 *
 * @package WP_Sentinel_Security
 * @var array $reports      Array of report objects.
 * @var int   $report_count Total number of reports.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

require SENTINEL_PLUGIN_DIR . 'admin/views/partials/header.php';
?>

<div class="wrap sentinel-wrap">

	<div class="sentinel-page-header">
		<div class="sentinel-header-left">
			<span class="dashicons dashicons-media-document sentinel-header-icon"></span>
			<div>
				<h1><?php esc_html_e( 'Security Reports', 'wp-sentinel-security' ); ?></h1>
				<span class="sentinel-subtitle"><?php esc_html_e( 'Generate and download security reports.', 'wp-sentinel-security' ); ?></span>
			</div>
		</div>
	</div>

	<!-- Generate Report Card -->
	<div class="sentinel-card">
		<h2><?php esc_html_e( 'Generate Report', 'wp-sentinel-security' ); ?></h2>
		<div class="sentinel-generate-form">
			<div class="sentinel-form-row">
				<label for="sentinel-report-type"><?php esc_html_e( 'Report Type', 'wp-sentinel-security' ); ?></label>
				<select id="sentinel-report-type" name="type">
					<option value="technical"><?php esc_html_e( 'Technical', 'wp-sentinel-security' ); ?></option>
					<option value="executive"><?php esc_html_e( 'Executive', 'wp-sentinel-security' ); ?></option>
					<option value="compliance"><?php esc_html_e( 'Compliance', 'wp-sentinel-security' ); ?></option>
				</select>
			</div>
			<div class="sentinel-form-row">
				<label for="sentinel-report-format"><?php esc_html_e( 'Format', 'wp-sentinel-security' ); ?></label>
				<select id="sentinel-report-format" name="format">
					<option value="html">HTML</option>
					<option value="json">JSON</option>
					<option value="csv">CSV</option>
				</select>
			</div>
			<div class="sentinel-form-row">
				<button id="sentinel-generate-report" class="button button-primary">
					<span class="dashicons dashicons-download" style="vertical-align:middle;margin-right:4px;"></span>
					<?php esc_html_e( 'Generate Report', 'wp-sentinel-security' ); ?>
				</button>
				<span id="sentinel-report-status" class="sentinel-status-msg" style="display:none;margin-left:12px;"></span>
			</div>
		</div>

		<!-- Progress bar (hidden until generation starts) -->
		<div id="sentinel-report-progress" style="display:none;margin-top:16px;">
			<div class="sentinel-progress-bar">
				<div class="sentinel-progress-fill" id="sentinel-progress-fill"></div>
			</div>
		</div>
	</div>

	<!-- Report History Table -->
	<div class="sentinel-card">
		<h2>
			<?php esc_html_e( 'Report History', 'wp-sentinel-security' ); ?>
			<span class="sentinel-count-badge"><?php echo esc_html( $report_count ); ?></span>
		</h2>

		<table class="sentinel-table widefat" id="sentinel-reports-table">
			<thead>
				<tr>
					<th><?php esc_html_e( 'Date', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'Title', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'Type', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'Format', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'Size', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'Actions', 'wp-sentinel-security' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php if ( ! empty( $reports ) ) : ?>
					<?php foreach ( $reports as $report ) : ?>
						<tr id="sentinel-report-row-<?php echo esc_attr( $report->id ); ?>">
							<td><?php echo esc_html( $report->created_at ); ?></td>
							<td><?php echo esc_html( $report->title ); ?></td>
							<td>
								<span class="sentinel-badge sentinel-badge-info">
									<?php echo esc_html( ucfirst( $report->report_type ) ); ?>
								</span>
							</td>
							<td>
								<span class="sentinel-format-badge sentinel-format-<?php echo esc_attr( $report->format ); ?>">
									<?php echo esc_html( strtoupper( $report->format ) ); ?>
								</span>
							</td>
							<td>
								<?php
								if ( ! empty( $report->file_path ) && file_exists( $report->file_path ) ) {
									echo esc_html( size_format( filesize( $report->file_path ) ) );
								} else {
									esc_html_e( '—', 'wp-sentinel-security' );
								}
								?>
							</td>
							<td>
								<a href="<?php echo esc_url( admin_url( 'admin-ajax.php?action=sentinel_download_report&report_id=' . absint( $report->id ) . '&nonce=' . wp_create_nonce( 'sentinel_nonce' ) ) ); ?>"
								   class="button button-small">
									<?php esc_html_e( 'Download', 'wp-sentinel-security' ); ?>
								</a>
								<button class="button button-small sentinel-delete-report"
								        data-id="<?php echo esc_attr( $report->id ); ?>"
								        style="margin-left:4px;">
									<?php esc_html_e( 'Delete', 'wp-sentinel-security' ); ?>
								</button>
							</td>
						</tr>
					<?php endforeach; ?>
				<?php else : ?>
					<tr id="sentinel-no-reports">
						<td colspan="6"><?php esc_html_e( 'No reports generated yet.', 'wp-sentinel-security' ); ?></td>
					</tr>
				<?php endif; ?>
			</tbody>
		</table>
	</div>

</div>

<script>
jQuery( function( $ ) {
	var nonce = '<?php echo esc_js( wp_create_nonce( 'sentinel_nonce' ) ); ?>';

	// Generate report.
	$( '#sentinel-generate-report' ).on( 'click', function() {
		var $btn    = $( this );
		var type    = $( '#sentinel-report-type' ).val();
		var format  = $( '#sentinel-report-format' ).val();
		var $status = $( '#sentinel-report-status' );
		var $bar    = $( '#sentinel-report-progress' );
		var $fill   = $( '#sentinel-progress-fill' );

		$btn.prop( 'disabled', true ).text( '<?php echo esc_js( __( 'Generating…', 'wp-sentinel-security' ) ); ?>' );
		$bar.show();
		$fill.css( 'width', '0%' ).animate( { width: '70%' }, 1500 );
		$status.hide();

		$.post(
			'<?php echo esc_js( admin_url( 'admin-ajax.php' ) ); ?>',
			{
				action: 'sentinel_generate_report',
				nonce:  nonce,
				type:   type,
				format: format
			},
			function( response ) {
				$fill.animate( { width: '100%' }, 300, function() {
					$bar.fadeOut( 500 );
					$fill.css( 'width', '0%' );
				} );

				if ( response.success ) {
					$status.text( response.data.message ).css( 'color', '#16a34a' ).show();
					$( '#sentinel-no-reports' ).hide();
					location.reload();
				} else {
					var msg = ( response.data && response.data.message ) ? response.data.message : '<?php echo esc_js( __( 'Generation failed.', 'wp-sentinel-security' ) ); ?>';
					$status.text( msg ).css( 'color', '#dc2626' ).show();
				}

				$btn.prop( 'disabled', false ).text( '<?php echo esc_js( __( 'Generate Report', 'wp-sentinel-security' ) ); ?>' );
			}
		).fail( function() {
			$bar.hide();
			$status.text( '<?php echo esc_js( __( 'Request failed. Please try again.', 'wp-sentinel-security' ) ); ?>' ).css( 'color', '#dc2626' ).show();
			$btn.prop( 'disabled', false ).text( '<?php echo esc_js( __( 'Generate Report', 'wp-sentinel-security' ) ); ?>' );
		} );
	} );

	// Delete report.
	$( document ).on( 'click', '.sentinel-delete-report', function() {
		if ( ! confirm( '<?php echo esc_js( __( 'Are you sure you want to delete this report? This action cannot be undone.', 'wp-sentinel-security' ) ); ?>' ) ) {
			return;
		}

		var $btn      = $( this );
		var reportId  = $btn.data( 'id' );

		$btn.prop( 'disabled', true );

		$.post(
			'<?php echo esc_js( admin_url( 'admin-ajax.php' ) ); ?>',
			{
				action:    'sentinel_delete_report',
				nonce:     nonce,
				report_id: reportId
			},
			function( response ) {
				if ( response.success ) {
					$( '#sentinel-report-row-' + reportId ).fadeOut( 300, function() {
						$( this ).remove();
					} );
				} else {
					var msg = ( response.data && response.data.message ) ? response.data.message : '<?php echo esc_js( __( 'Delete failed.', 'wp-sentinel-security' ) ); ?>';
					alert( msg );
					$btn.prop( 'disabled', false );
				}
			}
		).fail( function() {
			alert( '<?php echo esc_js( __( 'Request failed. Please try again.', 'wp-sentinel-security' ) ); ?>' );
			$btn.prop( 'disabled', false );
		} );
	} );
} );
</script>
