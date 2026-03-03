<?php
/**
 * Hardening view — Displays and controls all hardening checks.
 *
 * Expected variables passed from Sentinel_Admin::render_hardening():
 *
 * @var array[] $checks  All hardening checks from Hardening_Engine::get_all_checks().
 * @var int     $score   Overall hardening score (0–100) from Hardening_Engine::get_hardening_score().
 *
 * @package WP_Sentinel_Security
 * @since   2.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

require SENTINEL_PLUGIN_DIR . 'admin/views/partials/header.php';

// ── Category metadata ─────────────────────────────────────────────────────────
$category_labels = array(
	'file_security'     => __( 'File Security', 'wp-sentinel-security' ),
	'wp_config'         => __( 'WP Config Hardening', 'wp-sentinel-security' ),
	'server_config'     => __( 'Server Configuration', 'wp-sentinel-security' ),
	'user_security'     => __( 'User Security', 'wp-sentinel-security' ),
	'database_security' => __( 'Database Security', 'wp-sentinel-security' ),
	'api_security'      => __( 'API Security', 'wp-sentinel-security' ),
);

$category_icons = array(
	'file_security'     => 'dashicons-media-document',
	'wp_config'         => 'dashicons-admin-settings',
	'server_config'     => 'dashicons-admin-network',
	'user_security'     => 'dashicons-admin-users',
	'database_security' => 'dashicons-database',
	'api_security'      => 'dashicons-rest-api',
);

// ── Group checks by category ──────────────────────────────────────────────────
$checks_by_category = array();
foreach ( $checks as $check ) {
	$checks_by_category[ $check['category'] ][] = $check;
}

// ── Score grade helper ────────────────────────────────────────────────────────
$score_grade = 'F';
$score_class = 'sentinel-score-danger';
if ( $score >= 90 ) {
	$score_grade = 'A';
	$score_class = 'sentinel-score-excellent';
} elseif ( $score >= 75 ) {
	$score_grade = 'B';
	$score_class = 'sentinel-score-good';
} elseif ( $score >= 60 ) {
	$score_grade = 'C';
	$score_class = 'sentinel-score-fair';
} elseif ( $score >= 40 ) {
	$score_grade = 'D';
	$score_class = 'sentinel-score-poor';
}

// ── Count applied/partial/total ───────────────────────────────────────────────
$total_checks   = count( $checks );
$applied_count  = 0;
$partial_count  = 0;
foreach ( $checks as $check ) {
	if ( 'applied' === $check['status'] ) {
		$applied_count++;
	} elseif ( 'partial' === $check['status'] ) {
		$partial_count++;
	}
}
?>

<div class="wrap sentinel-wrap">

	<div class="sentinel-page-header">
		<div class="sentinel-header-left">
			<span class="dashicons dashicons-shield sentinel-header-icon"></span>
			<div>
				<h1><?php esc_html_e( 'Hardening Engine', 'wp-sentinel-security' ); ?></h1>
				<p class="sentinel-header-subtitle">
					<?php esc_html_e( 'Apply, monitor, and revert security hardening measures across your WordPress installation.', 'wp-sentinel-security' ); ?>
				</p>
			</div>
		</div>
		<div class="sentinel-header-actions">
			<button
				id="sentinel-apply-all-btn"
				class="button button-primary sentinel-apply-all"
				data-nonce="<?php echo esc_attr( wp_create_nonce( 'sentinel_hardening_nonce' ) ); ?>"
			>
				<span class="dashicons dashicons-yes-alt" style="vertical-align: middle; margin-right: 4px;"></span>
				<?php esc_html_e( 'Apply All Recommended', 'wp-sentinel-security' ); ?>
			</button>
		</div>
	</div>

	<!-- ── Overall Score Card ──────────────────────────────────────────────── -->
	<div class="sentinel-grid sentinel-grid-4" style="margin-bottom: 24px;">

		<div class="sentinel-card sentinel-score-card">
			<div class="sentinel-score-circle <?php echo esc_attr( $score_class ); ?>">
				<span class="sentinel-score-value"><?php echo esc_html( $score ); ?></span>
				<span class="sentinel-score-grade"><?php echo esc_html( $score_grade ); ?></span>
			</div>
			<p class="sentinel-score-label"><?php esc_html_e( 'Hardening Score', 'wp-sentinel-security' ); ?></p>
		</div>

		<div class="sentinel-card" style="display: flex; flex-direction: column; justify-content: center; align-items: center; text-align: center;">
			<span class="dashicons dashicons-yes-alt" style="font-size: 36px; color: #16a34a; width: 36px; height: 36px;"></span>
			<h2 style="margin: 8px 0 4px; font-size: 28px; color: #16a34a;">
				<?php echo esc_html( $applied_count ); ?>
			</h2>
			<p style="margin: 0; color: #6b7280;"><?php esc_html_e( 'Checks Applied', 'wp-sentinel-security' ); ?></p>
		</div>

		<div class="sentinel-card" style="display: flex; flex-direction: column; justify-content: center; align-items: center; text-align: center;">
			<span class="dashicons dashicons-warning" style="font-size: 36px; color: #d97706; width: 36px; height: 36px;"></span>
			<h2 style="margin: 8px 0 4px; font-size: 28px; color: #d97706;">
				<?php echo esc_html( $partial_count ); ?>
			</h2>
			<p style="margin: 0; color: #6b7280;"><?php esc_html_e( 'Partial', 'wp-sentinel-security' ); ?></p>
		</div>

		<div class="sentinel-card" style="display: flex; flex-direction: column; justify-content: center; align-items: center; text-align: center;">
			<span class="dashicons dashicons-dismiss" style="font-size: 36px; color: #dc2626; width: 36px; height: 36px;"></span>
			<h2 style="margin: 8px 0 4px; font-size: 28px; color: #dc2626;">
				<?php echo esc_html( $total_checks - $applied_count - $partial_count ); ?>
			</h2>
			<p style="margin: 0; color: #6b7280;"><?php esc_html_e( 'Not Applied', 'wp-sentinel-security' ); ?></p>
		</div>

	</div>

	<!-- ── Global notification area ────────────────────────────────────────── -->
	<div
		id="sentinel-hardening-notice"
		class="sentinel-notice"
		style="display: none;"
		role="alert"
		aria-live="polite"
		aria-atomic="true"
	>
		<span class="sentinel-notice-text"></span>
		<button
			type="button"
			class="sentinel-notice-dismiss"
			aria-label="<?php esc_attr_e( 'Dismiss notification', 'wp-sentinel-security' ); ?>"
			style="float: right; background: none; border: none; cursor: pointer; font-size: 16px; line-height: 1;"
		>&times;</button>
	</div>

	<!-- ── Checks grouped by category ─────────────────────────────────────── -->
	<?php foreach ( $checks_by_category as $category => $category_checks ) : ?>
		<?php
		$cat_label     = $category_labels[ $category ] ?? ucwords( str_replace( '_', ' ', $category ) );
		$cat_icon      = $category_icons[ $category ] ?? 'dashicons-admin-generic';
		$cat_applied   = count( array_filter( $category_checks, static function( $c ) { return 'applied' === $c['status']; } ) );
		$cat_total     = count( $category_checks );
		$accordion_id  = 'sentinel-accordion-' . esc_attr( $category );
		?>
		<div class="sentinel-card sentinel-accordion" id="<?php echo esc_attr( $accordion_id ); ?>">

			<!-- Accordion header / toggle -->
			<button
				class="sentinel-accordion-toggle"
				aria-expanded="true"
				aria-controls="<?php echo esc_attr( $accordion_id . '-body' ); ?>"
				type="button"
			>
				<span class="sentinel-accordion-title">
					<span class="dashicons <?php echo esc_attr( $cat_icon ); ?>" style="margin-right: 8px;"></span>
					<?php echo esc_html( $cat_label ); ?>
				</span>
				<span class="sentinel-accordion-meta">
					<span class="sentinel-badge sentinel-badge-<?php echo esc_attr( $cat_applied === $cat_total ? 'completed' : ( $cat_applied > 0 ? 'running' : 'pending' ) ); ?>">
						<?php
						echo esc_html(
							sprintf(
								/* translators: 1: applied count, 2: total count */
								__( '%1$d / %2$d applied', 'wp-sentinel-security' ),
								$cat_applied,
								$cat_total
							)
						);
						?>
					</span>
					<span class="dashicons dashicons-arrow-up-alt2 sentinel-accordion-chevron"></span>
				</span>
			</button>

			<!-- Accordion body -->
			<div class="sentinel-accordion-body" id="<?php echo esc_attr( $accordion_id . '-body' ); ?>">
				<?php foreach ( $category_checks as $check ) : ?>
					<?php
					$status      = $check['status'];
					$check_id    = esc_attr( $check['id'] );
					$risk        = $check['risk_level'];

					// Status badge config.
					$status_labels = array(
						'applied'     => __( '✅ Applied', 'wp-sentinel-security' ),
						'not_applied' => __( '❌ Not Applied', 'wp-sentinel-security' ),
						'partial'     => __( '⚠️ Partial', 'wp-sentinel-security' ),
						'unknown'     => __( '? Unknown', 'wp-sentinel-security' ),
					);
					$status_badge_map = array(
						'applied'     => 'completed',
						'not_applied' => 'failed',
						'partial'     => 'medium',
						'unknown'     => 'pending',
					);

					$status_label = $status_labels[ $status ] ?? $status_labels['unknown'];
					$status_badge = $status_badge_map[ $status ] ?? 'pending';

					// Risk badge config.
					$risk_badge_map = array(
						'critical' => 'critical',
						'high'     => 'high',
						'medium'   => 'medium',
						'low'      => 'low',
					);
					$risk_badge = $risk_badge_map[ $risk ] ?? 'info';
					?>
					<div
						class="sentinel-hardening-check"
						id="sentinel-check-<?php echo esc_attr( $check_id ); ?>"
						data-check-id="<?php echo esc_attr( $check_id ); ?>"
						data-status="<?php echo esc_attr( $status ); ?>"
					>
						<div class="sentinel-check-info">
							<div class="sentinel-check-header">
								<h3 class="sentinel-check-name"><?php echo esc_html( $check['name'] ); ?></h3>
								<div class="sentinel-check-badges">
									<span class="sentinel-badge sentinel-badge-<?php echo esc_attr( $risk_badge ); ?>">
										<?php
										echo esc_html(
											/* translators: %s: risk level name */
											sprintf( __( '%s Risk', 'wp-sentinel-security' ), ucfirst( $risk ) )
										);
										?>
									</span>
									<span
										class="sentinel-badge sentinel-badge-<?php echo esc_attr( $status_badge ); ?> sentinel-check-status-badge"
										role="status"
									>
										<?php echo esc_html( $status_label ); ?>
									</span>
								</div>
							</div>
							<p class="sentinel-check-description"><?php echo esc_html( $check['description'] ); ?></p>
							<?php if ( ! empty( $check['details'] ) ) : ?>
								<p class="sentinel-check-details">
									<em><?php echo esc_html( $check['details'] ); ?></em>
								</p>
							<?php endif; ?>
						</div>

						<div class="sentinel-check-actions">
							<button
								class="button button-primary sentinel-apply-check"
								data-check-id="<?php echo esc_attr( $check_id ); ?>"
								data-nonce="<?php echo esc_attr( wp_create_nonce( 'sentinel_hardening_nonce' ) ); ?>"
								<?php echo ( 'applied' === $status ) ? 'disabled aria-disabled="true"' : ''; ?>
							>
								<?php esc_html_e( 'Apply', 'wp-sentinel-security' ); ?>
							</button>
							<button
								class="button button-secondary sentinel-revert-check"
								data-check-id="<?php echo esc_attr( $check_id ); ?>"
								data-nonce="<?php echo esc_attr( wp_create_nonce( 'sentinel_hardening_nonce' ) ); ?>"
								<?php echo ( 'not_applied' === $status ) ? 'disabled aria-disabled="true"' : ''; ?>
							>
								<?php esc_html_e( 'Revert', 'wp-sentinel-security' ); ?>
							</button>
							<span class="sentinel-check-spinner spinner" style="float: none; margin: 0;"></span>
						</div>
					</div>
				<?php endforeach; ?>
			</div><!-- /.sentinel-accordion-body -->

		</div><!-- /.sentinel-card.sentinel-accordion -->
	<?php endforeach; ?>

</div><!-- /.wrap -->

<style>
/* ── Hardening-specific styles (scoped to sentinel-wrap) ── */
.sentinel-page-header {
	display: flex;
	align-items: center;
	justify-content: space-between;
	margin-bottom: 24px;
}
.sentinel-header-left {
	display: flex;
	align-items: flex-start;
	gap: 12px;
}
.sentinel-header-icon {
	font-size: 32px;
	width: 32px;
	height: 32px;
	color: var(--sentinel-primary, #2563eb);
	flex-shrink: 0;
}
.sentinel-header-subtitle {
	margin: 4px 0 0;
	color: #6b7280;
	font-size: 14px;
}
.sentinel-header-actions {
	flex-shrink: 0;
}

/* Score grades */
.sentinel-score-excellent { background: #f0fdf4; color: #16a34a; border-color: #16a34a; }
.sentinel-score-good      { background: #eff6ff; color: #2563eb; border-color: #2563eb; }
.sentinel-score-fair      { background: #fefce8; color: #ca8a04; border-color: #ca8a04; }
.sentinel-score-poor      { background: #fff7ed; color: #d97706; border-color: #d97706; }
.sentinel-score-danger    { background: #fef2f2; color: #dc2626; border-color: #dc2626; }

/* Notifications */
.sentinel-notice {
	padding: 12px 16px;
	border-radius: 6px;
	margin-bottom: 20px;
	font-size: 14px;
	border-left: 4px solid transparent;
}
.sentinel-notice-success {
	background: #f0fdf4;
	border-left-color: #16a34a;
	color: #166534;
}
.sentinel-notice-error {
	background: #fef2f2;
	border-left-color: #dc2626;
	color: #991b1b;
}
.sentinel-notice-info {
	background: #eff6ff;
	border-left-color: #2563eb;
	color: #1e40af;
}

/* Accordion */
.sentinel-accordion {
	padding: 0 !important;
	overflow: hidden;
}
.sentinel-accordion-toggle {
	width: 100%;
	display: flex;
	align-items: center;
	justify-content: space-between;
	padding: 16px 20px;
	background: none;
	border: none;
	cursor: pointer;
	font-size: 15px;
	font-weight: 600;
	color: inherit;
	text-align: left;
}
.sentinel-accordion-toggle:hover {
	background: #f9fafb;
}
.sentinel-accordion-title {
	display: flex;
	align-items: center;
}
.sentinel-accordion-meta {
	display: flex;
	align-items: center;
	gap: 10px;
}
.sentinel-accordion-chevron {
	transition: transform 0.2s;
}
.sentinel-accordion-toggle[aria-expanded="false"] .sentinel-accordion-chevron {
	transform: rotate(180deg);
}
.sentinel-accordion-body {
	border-top: 1px solid #e5e7eb;
}
.sentinel-accordion-body[hidden] {
	display: none;
}

/* Individual check row */
.sentinel-hardening-check {
	display: flex;
	align-items: flex-start;
	justify-content: space-between;
	gap: 20px;
	padding: 16px 20px;
	border-bottom: 1px solid #f3f4f6;
}
.sentinel-hardening-check:last-child {
	border-bottom: none;
}
.sentinel-check-info {
	flex: 1;
	min-width: 0;
}
.sentinel-check-header {
	display: flex;
	align-items: flex-start;
	flex-wrap: wrap;
	gap: 8px;
	margin-bottom: 6px;
}
.sentinel-check-name {
	margin: 0;
	font-size: 14px;
	font-weight: 600;
}
.sentinel-check-badges {
	display: flex;
	gap: 6px;
	flex-wrap: wrap;
}
.sentinel-check-description {
	margin: 0 0 4px;
	font-size: 13px;
	color: #374151;
}
.sentinel-check-details {
	margin: 0;
	font-size: 12px;
	color: #6b7280;
}
.sentinel-check-actions {
	display: flex;
	align-items: center;
	gap: 8px;
	flex-shrink: 0;
}
.sentinel-check-actions .button {
	white-space: nowrap;
}
.sentinel-check-spinner {
	visibility: hidden;
}
.sentinel-check-spinner.is-active {
	visibility: visible;
}

@media ( max-width: 782px ) {
	.sentinel-hardening-check {
		flex-direction: column;
	}
	.sentinel-check-actions {
		width: 100%;
		justify-content: flex-start;
	}
	.sentinel-page-header {
		flex-direction: column;
		align-items: flex-start;
		gap: 12px;
	}
}
</style>

<script>
/* global sentinelData */
( function( $ ) {
	'use strict';

	/**
	 * WP Sentinel Security — Hardening Engine UI
	 * Handles Apply / Revert / Apply-All actions via AJAX.
	 */
	var SentinelHardening = {

		ajaxUrl: ( typeof sentinelData !== 'undefined' ) ? sentinelData.ajaxUrl : ajaxurl,
		nonce:   ( typeof sentinelData !== 'undefined' ) ? sentinelData.nonces.hardening : '',

		/**
		 * Initialise event bindings.
		 */
		init: function() {
			$( document ).on( 'click', '.sentinel-apply-check',  this.applyCheck.bind( this ) );
			$( document ).on( 'click', '.sentinel-revert-check', this.revertCheck.bind( this ) );
			$( document ).on( 'click', '.sentinel-apply-all',    this.applyAll.bind( this ) );
			$( document ).on( 'click', '.sentinel-accordion-toggle', this.toggleAccordion.bind( this ) );
			$( document ).on( 'click', '.sentinel-notice-dismiss', this.dismissNotice.bind( this ) );
		},

		/**
		 * Toggle accordion sections open / closed.
		 *
		 * @param {jQuery.Event} e Click event.
		 */
		toggleAccordion: function( e ) {
			var $btn    = $( e.currentTarget );
			var $body   = $( '#' + $btn.attr( 'aria-controls' ) );
			var expanded = 'true' === $btn.attr( 'aria-expanded' );

			$btn.attr( 'aria-expanded', expanded ? 'false' : 'true' );

			if ( expanded ) {
				$body.attr( 'hidden', true );
			} else {
				$body.removeAttr( 'hidden' );
			}
		},

		/**
		 * Apply a single hardening check.
		 *
		 * @param {jQuery.Event} e Click event.
		 */
		applyCheck: function( e ) {
			var $btn     = $( e.currentTarget );
			var checkId  = $btn.data( 'check-id' );
			var nonce    = $btn.data( 'nonce' ) || this.nonce;
			var $row     = $( '#sentinel-check-' + checkId );
			var $spinner = $row.find( '.sentinel-check-spinner' );

			$btn.prop( 'disabled', true );
			$spinner.addClass( 'is-active' );

			this.request( 'sentinel_apply_hardening', { check_id: checkId, nonce: nonce }, function( response ) {
				$spinner.removeClass( 'is-active' );

				if ( response.success ) {
					SentinelHardening.updateCheckRow( $row, response.data.check_status );
					SentinelHardening.updateScore( response.data.score );
					SentinelHardening.showNotice(
						'success',
						response.data.result.message || '<?php echo esc_js( __( 'Check applied successfully.', 'wp-sentinel-security' ) ); ?>'
					);
				} else {
					$btn.prop( 'disabled', false );
					SentinelHardening.showNotice(
						'error',
						( response.data && response.data.message ) || '<?php echo esc_js( __( 'An error occurred. Please try again.', 'wp-sentinel-security' ) ); ?>'
					);
				}
			} );
		},

		/**
		 * Revert a single hardening check.
		 *
		 * @param {jQuery.Event} e Click event.
		 */
		revertCheck: function( e ) {
			var $btn     = $( e.currentTarget );
			var checkId  = $btn.data( 'check-id' );
			var nonce    = $btn.data( 'nonce' ) || this.nonce;
			var $row     = $( '#sentinel-check-' + checkId );
			var $spinner = $row.find( '.sentinel-check-spinner' );

			$btn.prop( 'disabled', true );
			$spinner.addClass( 'is-active' );

			this.request( 'sentinel_revert_hardening', { check_id: checkId, nonce: nonce }, function( response ) {
				$spinner.removeClass( 'is-active' );

				if ( response.success ) {
					SentinelHardening.updateCheckRow( $row, response.data.check_status );
					SentinelHardening.updateScore( response.data.score );
					SentinelHardening.showNotice(
						'info',
						response.data.result.message || '<?php echo esc_js( __( 'Check reverted.', 'wp-sentinel-security' ) ); ?>'
					);
				} else {
					$btn.prop( 'disabled', false );
					SentinelHardening.showNotice(
						'error',
						( response.data && response.data.message ) || '<?php echo esc_js( __( 'An error occurred. Please try again.', 'wp-sentinel-security' ) ); ?>'
					);
				}
			} );
		},

		/**
		 * Apply all checks that are not yet applied.
		 *
		 * @param {jQuery.Event} e Click event.
		 */
		applyAll: function( e ) {
			var $btn   = $( e.currentTarget );
			var nonce  = $btn.data( 'nonce' ) || this.nonce;

			$btn.prop( 'disabled', true )
				.text( '<?php echo esc_js( __( 'Applying…', 'wp-sentinel-security' ) ); ?>' );

			var $pending = $( '.sentinel-hardening-check[data-status!="applied"]' );
			var total    = $pending.length;
			var done     = 0;

			if ( 0 === total ) {
				$btn.prop( 'disabled', false )
					.text( '<?php echo esc_js( __( 'Apply All Recommended', 'wp-sentinel-security' ) ); ?>' );
				SentinelHardening.showNotice( 'info', '<?php echo esc_js( __( 'All recommended checks are already applied.', 'wp-sentinel-security' ) ); ?>' );
				return;
			}

			/**
			 * Apply checks sequentially to avoid overwhelming the server.
			 *
			 * @param {number} index Current check index.
			 */
			function applyNext( index ) {
				if ( index >= total ) {
					$btn.prop( 'disabled', false )
						.text( '<?php echo esc_js( __( 'Apply All Recommended', 'wp-sentinel-security' ) ); ?>' );
					SentinelHardening.showNotice(
						'success',
						'<?php echo esc_js( __( 'All applicable checks have been processed.', 'wp-sentinel-security' ) ); ?>'
					);
					return;
				}

				var $row    = $( $pending[ index ] );
				var checkId = $row.data( 'check-id' );
				var $spinner = $row.find( '.sentinel-check-spinner' );

				$spinner.addClass( 'is-active' );

				SentinelHardening.request(
					'sentinel_apply_hardening',
					{ check_id: checkId, nonce: nonce },
					function( response ) {
						$spinner.removeClass( 'is-active' );
						if ( response.success ) {
							SentinelHardening.updateCheckRow( $row, response.data.check_status );
							SentinelHardening.updateScore( response.data.score );
						}
						done++;
						applyNext( index + 1 );
					}
				);
			}

			applyNext( 0 );
		},

		/**
		 * Update a check row's status badge and button states.
		 *
		 * @param {jQuery} $row       The check row element.
		 * @param {Object} checkStatus Status object with `status` and `details` keys.
		 */
		updateCheckRow: function( $row, checkStatus ) {
			var status = checkStatus.status;
			var details = checkStatus.details || '';

			var labelMap = {
				applied:     '<?php echo esc_js( __( '✅ Applied', 'wp-sentinel-security' ) ); ?>',
				not_applied: '<?php echo esc_js( __( '❌ Not Applied', 'wp-sentinel-security' ) ); ?>',
				partial:     '<?php echo esc_js( __( '⚠️ Partial', 'wp-sentinel-security' ) ); ?>',
				unknown:     '<?php echo esc_js( __( '? Unknown', 'wp-sentinel-security' ) ); ?>',
			};

			var badgeMap = {
				applied:     'sentinel-badge-completed',
				not_applied: 'sentinel-badge-failed',
				partial:     'sentinel-badge-medium',
				unknown:     'sentinel-badge-pending',
			};

			var $badge = $row.find( '.sentinel-check-status-badge' );
			$badge.attr( 'class', 'sentinel-badge sentinel-check-status-badge ' + ( badgeMap[ status ] || 'sentinel-badge-pending' ) );
			$badge.text( labelMap[ status ] || status );

			if ( details ) {
				var $detailsEl = $row.find( '.sentinel-check-details' );
				if ( $detailsEl.length ) {
					$detailsEl.text( details );
				}
			}

			$row.attr( 'data-status', status );

			$row.find( '.sentinel-apply-check' ).prop( 'disabled', 'applied' === status );
			$row.find( '.sentinel-revert-check' ).prop( 'disabled', 'not_applied' === status );
		},

		/**
		 * Update the overall score display.
		 *
		 * @param {number} score New score (0–100).
		 */
		updateScore: function( score ) {
			$( '.sentinel-score-value' ).text( score );
		},

		/**
		 * Display a notification banner at the top of the page.
		 *
		 * @param {string} type    'success' | 'error' | 'info'.
		 * @param {string} message The message text to display.
		 */
		showNotice: function( type, message ) {
			var $notice = $( '#sentinel-hardening-notice' );
			// Rebuild the notice content preserving the dismiss button.
			$notice
				.attr( 'class', 'sentinel-notice sentinel-notice-' + type )
				.show()
				.find( '.sentinel-notice-text' )
				.text( message );

			// Allow assistive technologies adequate time — auto-dismiss after 10 s.
			clearTimeout( SentinelHardening._noticeTimer );
			SentinelHardening._noticeTimer = setTimeout( function() {
				$notice.fadeOut();
			}, 10000 );
		},

		/**
		 * Manually dismiss the notification banner.
		 */
		dismissNotice: function() {
			clearTimeout( SentinelHardening._noticeTimer );
			$( '#sentinel-hardening-notice' ).fadeOut();
		},

		/**
		 * Perform an AJAX request.
		 *
		 * @param {string}   action   WordPress AJAX action name.
		 * @param {Object}   data     POST data to send.
		 * @param {Function} callback Called with the parsed response object.
		 */
		request: function( action, data, callback ) {
			$.ajax( {
				url:    this.ajaxUrl,
				method: 'POST',
				data:   $.extend( { action: action }, data ),
				success: callback,
				error: function() {
					callback( { success: false, data: { message: '<?php echo esc_js( __( 'Network error. Please try again.', 'wp-sentinel-security' ) ); ?>' } } );
				},
			} );
		},

		/** @type {number} Timer ID for notice auto-dismiss. */
		_noticeTimer: null,
	};

	$( function() {
		SentinelHardening.init();
	} );

}( jQuery ) );
</script>
