<?php
/**
 * Backups admin view.
 *
 * Renders the backup management page: storage summary, backup creation form
 * with progress tracking, and the paginated backup history table.
 *
 * @package WP_Sentinel_Security
 * @var array  $backups      Array of stdClass backup objects (non-deleted).
 * @var int    $storage_size Total backup storage used in bytes.
 * @var int    $backup_count Total number of backups.
 * @since 1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

require SENTINEL_PLUGIN_DIR . 'admin/views/partials/header.php';

/**
 * Format a byte count as a human-readable string.
 *
 * @param int $bytes Number of bytes.
 * @return string
 */
function sentinel_format_bytes( $bytes ) {
	$bytes = (int) $bytes;
	if ( $bytes >= 1073741824 ) {
		return round( $bytes / 1073741824, 2 ) . ' GB';
	}
	if ( $bytes >= 1048576 ) {
		return round( $bytes / 1048576, 2 ) . ' MB';
	}
	if ( $bytes >= 1024 ) {
		return round( $bytes / 1024, 2 ) . ' KB';
	}
	return $bytes . ' B';
}

// Last backup date from first item (already ordered DESC).
$last_backup_date = ! empty( $backups ) ? $backups[0]->created_at : null;
?>

<div class="wrap sentinel-wrap">

	<div class="sentinel-page-header">
		<div class="sentinel-header-left">
			<span class="dashicons dashicons-backup sentinel-header-icon"></span>
			<h1><?php esc_html_e( 'Backups', 'wp-sentinel-security' ); ?></h1>
		</div>
	</div>

	<!-- Storage Summary -->
	<div class="sentinel-grid sentinel-grid-3">

		<div class="sentinel-card sentinel-stat-card">
			<span class="dashicons dashicons-database sentinel-stat-icon"></span>
			<div class="sentinel-stat-value"><?php echo esc_html( sentinel_format_bytes( $storage_size ) ); ?></div>
			<div class="sentinel-stat-label"><?php esc_html_e( 'Total Storage Used', 'wp-sentinel-security' ); ?></div>
		</div>

		<div class="sentinel-card sentinel-stat-card">
			<span class="dashicons dashicons-backup sentinel-stat-icon"></span>
			<div class="sentinel-stat-value"><?php echo esc_html( $backup_count ); ?></div>
			<div class="sentinel-stat-label"><?php esc_html_e( 'Total Backups', 'wp-sentinel-security' ); ?></div>
		</div>

		<div class="sentinel-card sentinel-stat-card">
			<span class="dashicons dashicons-calendar-alt sentinel-stat-icon"></span>
			<div class="sentinel-stat-value">
				<?php
				echo $last_backup_date
					? esc_html( date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), strtotime( $last_backup_date ) ) )
					: esc_html__( 'Never', 'wp-sentinel-security' );
				?>
			</div>
			<div class="sentinel-stat-label"><?php esc_html_e( 'Last Backup', 'wp-sentinel-security' ); ?></div>
		</div>

	</div>

	<!-- Create Backup -->
	<div class="sentinel-card" id="sentinel-create-backup-card">
		<h2><?php esc_html_e( 'Create Backup', 'wp-sentinel-security' ); ?></h2>
		<p><?php esc_html_e( 'Select the type of backup you want to create.', 'wp-sentinel-security' ); ?></p>

		<div class="sentinel-backup-type-selector">
			<label class="sentinel-radio-label">
				<input type="radio" name="sentinel_backup_type" value="full" checked="checked">
				<strong><?php esc_html_e( 'Full Backup', 'wp-sentinel-security' ); ?></strong>
				<span><?php esc_html_e( '— Database + Files', 'wp-sentinel-security' ); ?></span>
			</label>
			<label class="sentinel-radio-label">
				<input type="radio" name="sentinel_backup_type" value="database">
				<strong><?php esc_html_e( 'Database Only', 'wp-sentinel-security' ); ?></strong>
				<span><?php esc_html_e( '— SQL dump of all tables', 'wp-sentinel-security' ); ?></span>
			</label>
			<label class="sentinel-radio-label">
				<input type="radio" name="sentinel_backup_type" value="files">
				<strong><?php esc_html_e( 'Files Only', 'wp-sentinel-security' ); ?></strong>
				<span><?php esc_html_e( '— ZIP archive of wp-content', 'wp-sentinel-security' ); ?></span>
			</label>
		</div>

		<button class="button button-primary sentinel-btn" id="sentinel-start-backup">
			<?php esc_html_e( 'Create Backup', 'wp-sentinel-security' ); ?>
		</button>

		<!-- Progress (hidden by default) -->
		<div id="sentinel-backup-progress-wrap" style="display:none; margin-top:16px;">
			<div class="sentinel-progress-bar-wrap">
				<div class="sentinel-progress-bar">
					<div class="sentinel-progress-fill" id="sentinelBackupProgressFill" style="width:0%"></div>
				</div>
				<span id="sentinelBackupProgressText">0%</span>
			</div>
			<p id="sentinelBackupStatusMsg" class="sentinel-status-msg">
				<?php esc_html_e( 'Preparing backup…', 'wp-sentinel-security' ); ?>
			</p>
		</div>

		<!-- Result message -->
		<div id="sentinel-backup-result" style="display:none;" class="notice" role="alert"></div>
	</div>

	<!-- Backup History -->
	<div class="sentinel-card">
		<h2><?php esc_html_e( 'Backup History', 'wp-sentinel-security' ); ?></h2>

		<?php if ( ! empty( $backups ) ) : ?>
		<table class="sentinel-table widefat" id="sentinel-backups-table">
			<thead>
				<tr>
					<th><?php esc_html_e( 'Date', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'Type', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'Size', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'Status', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'Checksum', 'wp-sentinel-security' ); ?></th>
					<th><?php esc_html_e( 'Actions', 'wp-sentinel-security' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php foreach ( $backups as $backup ) : ?>
					<?php
					$checksum_short = ! empty( $backup->checksum ) ? substr( $backup->checksum, 0, 8 ) : '—';
					$status_class   = 'sentinel-badge-' . esc_attr( $backup->status );
					?>
					<tr id="sentinel-backup-row-<?php echo esc_attr( $backup->id ); ?>">
						<td><?php echo esc_html( date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), strtotime( $backup->created_at ) ) ); ?></td>
						<td><?php echo esc_html( ucfirst( $backup->backup_type ) ); ?></td>
						<td><?php echo esc_html( sentinel_format_bytes( $backup->file_size ) ); ?></td>
						<td>
							<span class="sentinel-badge <?php echo esc_attr( $status_class ); ?>">
								<?php echo esc_html( ucfirst( $backup->status ) ); ?>
							</span>
						</td>
						<td>
							<code title="<?php echo esc_attr( $backup->checksum ); ?>">
								<?php echo esc_html( $checksum_short ); ?>…
							</code>
						</td>
						<td class="sentinel-actions">
							<?php if ( 'completed' === $backup->status && file_exists( $backup->file_path ) ) : ?>
								<a
									href="<?php echo esc_url( admin_url( 'admin-post.php?action=sentinel_download_backup&backup_id=' . absint( $backup->id ) . '&_wpnonce=' . wp_create_nonce( 'sentinel_download_backup_' . $backup->id ) ) ); ?>"
									class="button button-small sentinel-btn sentinel-btn-secondary"
								>
									<?php esc_html_e( 'Download', 'wp-sentinel-security' ); ?>
								</a>

								<button
									class="button button-small sentinel-btn sentinel-btn-warning sentinel-restore-backup"
									data-backup-id="<?php echo esc_attr( $backup->id ); ?>"
								>
									<?php esc_html_e( 'Restore', 'wp-sentinel-security' ); ?>
								</button>
							<?php endif; ?>

							<button
								class="button button-small sentinel-btn sentinel-btn-danger sentinel-delete-backup"
								data-backup-id="<?php echo esc_attr( $backup->id ); ?>"
							>
								<?php esc_html_e( 'Delete', 'wp-sentinel-security' ); ?>
							</button>
						</td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
		<?php else : ?>
			<p><?php esc_html_e( 'No backups found. Create your first backup above.', 'wp-sentinel-security' ); ?></p>
		<?php endif; ?>
	</div>

</div><!-- .sentinel-wrap -->

<script type="text/javascript">
/* global sentinelData */
( function ( $ ) {
	'use strict';

	var progressTimer = null;

	/**
	 * Poll the progress endpoint and update the progress bar UI.
	 */
	function pollProgress() {
		$.post(
			sentinelData.ajaxUrl,
			{
				action : 'sentinel_get_backup_progress',
				nonce  : sentinelData.nonces.backup
			},
			function ( response ) {
				if ( response.success ) {
					var pct = parseInt( response.data.progress, 10 ) || 0;
					$( '#sentinelBackupProgressFill' ).css( 'width', pct + '%' );
					$( '#sentinelBackupProgressText' ).text( pct + '%' );

					if ( pct < 100 ) {
						progressTimer = setTimeout( pollProgress, 2000 );
					}
				}
			}
		);
	}

	/**
	 * Show a result message in the result div.
	 *
	 * @param {string}  message  Text to display.
	 * @param {boolean} success  True for success, false for error.
	 */
	function showResult( message, success ) {
		var $result = $( '#sentinel-backup-result' );
		$result
			.removeClass( 'notice-success notice-error' )
			.addClass( success ? 'notice-success' : 'notice-error' )
			.text( message )
			.show();
	}

	/**
	 * Handle Create Backup button click.
	 */
	$( '#sentinel-start-backup' ).on( 'click', function () {
		var type = $( 'input[name="sentinel_backup_type"]:checked' ).val() || 'full';

		$( '#sentinel-backup-result' ).hide();
		$( '#sentinel-backup-progress-wrap' ).show();
		$( '#sentinel-start-backup' ).prop( 'disabled', true );
		$( '#sentinelBackupStatusMsg' ).text( sentinelData.i18n.backupCreating );

		// Start progress polling.
		progressTimer = setTimeout( pollProgress, 2000 );

		$.post(
			sentinelData.ajaxUrl,
			{
				action : 'sentinel_create_backup',
				nonce  : sentinelData.nonces.backup,
				type   : type
			},
			function ( response ) {
				clearTimeout( progressTimer );

				$( '#sentinelBackupProgressFill' ).css( 'width', '100%' );
				$( '#sentinelBackupProgressText' ).text( '100%' );
				$( '#sentinel-start-backup' ).prop( 'disabled', false );

				if ( response.success ) {
					$( '#sentinelBackupStatusMsg' ).text( sentinelData.i18n.backupComplete );
					showResult( sentinelData.i18n.backupComplete, true );
					// Reload to show new backup in table.
					setTimeout( function () {
						window.location.reload();
					}, 1500 );
				} else {
					var msg = ( response.data && response.data.message )
						? response.data.message
						: sentinelData.i18n.backupFailed;
					$( '#sentinelBackupStatusMsg' ).text( msg );
					showResult( msg, false );
					$( '#sentinel-backup-progress-wrap' ).hide();
				}
			}
		).fail( function () {
			clearTimeout( progressTimer );
			$( '#sentinel-start-backup' ).prop( 'disabled', false );
			showResult( sentinelData.i18n.backupFailed, false );
			$( '#sentinel-backup-progress-wrap' ).hide();
		} );
	} );

	/**
	 * Handle Restore backup button clicks.
	 */
	$( document ).on( 'click', '.sentinel-restore-backup', function () {
		var backupId = $( this ).data( 'backup-id' );

		// eslint-disable-next-line no-alert
		if ( ! window.confirm( sentinelData.i18n.confirmRestore ) ) {
			return;
		}

		var $btn = $( this ).prop( 'disabled', true ).text( '…' );

		$.post(
			sentinelData.ajaxUrl,
			{
				action    : 'sentinel_restore_backup',
				nonce     : sentinelData.nonces.backup,
				backup_id : backupId
			},
			function ( response ) {
				$btn.prop( 'disabled', false ).text( sentinelData.i18n.restore || 'Restore' );

				if ( response.success ) {
					showResult( response.data.message, true );
				} else {
					var msg = ( response.data && response.data.message )
						? response.data.message
						: sentinelData.i18n.backupFailed;
					showResult( msg, false );
				}
			}
		).fail( function () {
			$btn.prop( 'disabled', false ).text( sentinelData.i18n.restore || 'Restore' );
			showResult( sentinelData.i18n.backupFailed, false );
		} );
	} );

	/**
	 * Handle Delete backup button clicks.
	 */
	$( document ).on( 'click', '.sentinel-delete-backup', function () {
		var backupId = $( this ).data( 'backup-id' );

		// eslint-disable-next-line no-alert
		if ( ! window.confirm( sentinelData.i18n.confirmDelete ) ) {
			return;
		}

		var $row = $( '#sentinel-backup-row-' + backupId );
		var $btn = $( this ).prop( 'disabled', true );

		$.post(
			sentinelData.ajaxUrl,
			{
				action    : 'sentinel_delete_backup',
				nonce     : sentinelData.nonces.backup,
				backup_id : backupId
			},
			function ( response ) {
				if ( response.success ) {
					$row.fadeOut( 400, function () {
						$( this ).remove();
					} );
				} else {
					$btn.prop( 'disabled', false );
					var msg = ( response.data && response.data.message )
						? response.data.message
						: sentinelData.i18n.backupFailed;
					showResult( msg, false );
				}
			}
		).fail( function () {
			$btn.prop( 'disabled', false );
			showResult( sentinelData.i18n.backupFailed, false );
		} );
	} );

} )( jQuery );
</script>
