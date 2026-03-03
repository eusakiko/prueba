/**
 * WP Sentinel Security — Scanner-specific JS
 *
 * Handles severity filter tabs and vuln detail expand/collapse.
 *
 * @package WP_Sentinel_Security
 */
( function ( $ ) {
	'use strict';

	var SentinelScanner = {

		/**
		 * Initialise scanner page interactions.
		 */
		init: function () {
			this.bindEvents();
		},

		/**
		 * Bind UI events.
		 */
		bindEvents: function () {
			// Severity filter tabs.
			$( document ).on( 'click', '.sentinel-tab', this.filterBySeverity.bind( this ) );

			// Expand/collapse vulnerability details.
			$( document ).on( 'click', '.sentinel-vuln-details', this.toggleVulnDetails.bind( this ) );
		},

		/**
		 * Filter vulnerabilities table by severity.
		 *
		 * @param {jQuery.Event} e Click event.
		 */
		filterBySeverity: function ( e ) {
			var $tab    = $( e.currentTarget );
			var filter  = $tab.data( 'filter' );

			// Update active tab.
			$( '.sentinel-tab' ).removeClass( 'active' );
			$tab.addClass( 'active' );

			// Filter rows.
			var $rows = $( '#sentinelResultsTable tbody tr[data-severity]' );
			if ( 'all' === filter ) {
				$rows.show();
			} else {
				$rows.hide().filter( '[data-severity="' + filter + '"]' ).show();
			}
		},

		/**
		 * Toggle vulnerability detail row.
		 *
		 * @param {jQuery.Event} e Click event.
		 */
		toggleVulnDetails: function ( e ) {
			var $btn     = $( e.currentTarget );
			var $row     = $btn.closest( 'tr' );
			var $details = $row.next( '.sentinel-vuln-detail-row' );

			if ( $details.length ) {
				$details.toggle();
				return;
			}

			// Fetch details via AJAX and insert a new row.
			var vulnId = parseInt( $btn.data( 'id' ), 10 );

			$.ajax( {
				url:    window.sentinelData ? sentinelData.restUrl + 'vulnerabilities/' + vulnId : '',
				method: 'GET',
				beforeSend: function ( xhr ) {
					if ( window.sentinelData && sentinelData.nonces ) {
						xhr.setRequestHeader( 'X-WP-Nonce', sentinelData.nonces.scan );
					}
				},
				success: function ( vuln ) {
					var html = '<tr class="sentinel-vuln-detail-row">' +
						'<td colspan="5" style="background:#f9fafb;padding:16px;">' +
						'<strong>' + sentinelData.i18n.whatThisMeans + '</strong><p>' + $( '<span>' ).text( vuln.description || '' ).html() + '</p>' +
						'<strong>' + sentinelData.i18n.whatToDoNext + '</strong><p>' + $( '<span>' ).text( vuln.recommendation || '' ).html() + '</p>' +
						( vuln.cvss_vector ? '<details><summary><strong>Advanced details</strong></summary><p>' + $( '<span>' ).text( vuln.cvss_vector ).html() + '</p></details>' : '' ) +
						'</td></tr>';
					$row.after( html );
				},
				error: function () {
					var html = '<tr class="sentinel-vuln-detail-row">' +
						'<td colspan="5"><em>' + sentinelData.i18n.detailsUnavailable + '</em></td></tr>';
					$row.after( html );
				},
			} );
		},
	};

	$( function () {
		SentinelScanner.init();

		// ── Vulnerability CSV export ──────────────────────────────────────────
		var currentExportScanId = 0;

		$( document ).on( 'sentinel:results_loaded', function ( e, scanId ) {
			currentExportScanId = scanId || 0;
		} );

		$( '#sentinel-export-vuln-btn' ).on( 'click', function () {
			var $btn   = $( this ).prop( 'disabled', true );
			var status = $( '#sentinel-export-status' ).val() || 'open';
			var nonce  = ( window.sentinelData && sentinelData.nonces ) ? sentinelData.nonces.scan : '';
			var params = { action: 'sentinel_export_vulnerabilities', nonce: nonce, status: status };
			if ( currentExportScanId > 0 ) { params.scan_id = currentExportScanId; }
			var url = ajaxurl + '?' + $.param( params );
			var $a  = $( '<a>' ).attr( { href: url, download: '' } ).appendTo( 'body' );
			$a[ 0 ].click();
			$a.remove();
			setTimeout( function () { $btn.prop( 'disabled', false ); }, 1500 );
		} );

		// ── Helpers ────────────────────────────────────────────────────────────
		var severityColors = {
			critical: '#dc2626', high: '#ea580c',
			medium: '#ca8a04',   low: '#16a34a', info: '#2563eb'
		};

		function severityBadge( sev ) {
			return '<span class="sentinel-badge sentinel-badge-' + sev + '">' + sev.charAt(0).toUpperCase() + sev.slice(1) + '</span>';
		}

		function buildVulnRows( vulns ) {
			if ( ! vulns || ! vulns.length ) {
				return '<tr><td colspan="6" style="text-align:center;color:#94a3b8;">No vulnerabilities in this category.</td></tr>';
			}
			return vulns.map( function ( v ) {
				return '<tr data-severity="' + v.severity + '">' +
					'<td>' + severityBadge( v.severity ) + '</td>' +
					'<td><strong>' + $( '<span>' ).text( v.component_name ).html() + '</strong>' +
						( v.component_version ? ' <small style="color:#94a3b8;">v' + $( '<span>' ).text( v.component_version ).html() + '</small>' : '' ) + '</td>' +
					'<td>' + $( '<span>' ).text( v.title ).html() +
						( v.vulnerability_id ? ' <span style="font-size:11px;color:#2563eb;background:#eff6ff;padding:1px 6px;border-radius:3px;">' + $( '<span>' ).text( v.vulnerability_id ).html() + '</span>' : '' ) + '</td>' +
					'<td>' + ( v.cvss_score || '—' ) + '</td>' +
					'<td style="font-size:11px;color:#94a3b8;">' + ( v.detected_at ? v.detected_at.split(' ')[0] : '—' ) + '</td>' +
					'<td><button class="button button-small sentinel-fix-btn" data-id="' + v.id + '" data-status="fixed">' +
						'Mark Fixed</button></td>' +
				'</tr>';
			} ).join( '' );
		}

		// ── Open Issues panel ─────────────────────────────────────────────────
		var openIssuesData = null;

		// Delegated handler for the "Mark Fixed" buttons rendered inside the
		// Open Issues table rows (the table is injected dynamically so direct
		// binding won't work — we delegate from the static parent).
		$( '#sentinel-open-issues-table' ).on( 'click', '.sentinel-fix-btn', function () {
			var $btn   = $( this ).prop( 'disabled', true ).text( 'Saving…' );
			var vulnId = $btn.data( 'id' );
			var status = $btn.data( 'status' ) || 'fixed';
			var nonce  = ( window.sentinelData && sentinelData.nonces ) ? sentinelData.nonces.scan : '';

			$.post( sentinelData.ajaxUrl || ajaxurl, {
				action:      'sentinel_mark_vulnerability',
				vuln_id:     vulnId,
				vuln_action: status,
				nonce:       nonce,
			}, function ( r ) {
				if ( r.success ) {
					$btn.closest( 'tr' ).fadeOut( 300, function () {
						$( this ).remove();
					} );
				} else {
					$btn.prop( 'disabled', false ).text( 'Mark Fixed' );
					alert( ( r.data && r.data.message ) ? r.data.message : 'Error updating status.' );
				}
			} ).fail( function () {
				$btn.prop( 'disabled', false ).text( 'Mark Fixed' );
			} );
		} );

		$( '#sentinel-load-open-issues' ).on( 'click', function () {
			var $btn   = $( this ).prop( 'disabled', true ).text( 'Loading…' );
			var $panel = $( '#sentinel-open-issues-panel' );
			var nonce  = ( window.sentinelData && sentinelData.nonces ) ? sentinelData.nonces.scan : '';

			$.post( ajaxurl, {
				action: 'sentinel_get_open_vulnerabilities',
				nonce:  nonce
			}, function ( r ) {
				$btn.prop( 'disabled', false ).html( '⚠ View Open Issues' );

				if ( ! r.success ) {
					$panel.show().html(
						'<p style="color:#dc2626;">' + ( r.data && r.data.message ? r.data.message : 'Error loading issues.' ) + '</p>'
					);
					return;
				}

				openIssuesData = r.data.vulnerabilities || [];
				var total       = r.data.total || 0;
				var bySev       = r.data.by_severity || {};

				// Update badge.
				var critHigh = ( bySev.critical || 0 ) + ( bySev.high || 0 );
				var $badge   = $( '#sentinel-open-count-badge' );
				$badge.text( total + ' open' + ( critHigh ? ' (' + critHigh + ' critical/high)' : '' ) ).show();

				$( '#sentinel-open-issues-body' ).html( buildVulnRows( openIssuesData ) );
				$panel.show();

				// Severity filter tabs.
				$( '#sentinel-open-filter-tabs .sentinel-tab' ).on( 'click', function () {
					$( '#sentinel-open-filter-tabs .sentinel-tab' ).removeClass( 'active' );
					$( this ).addClass( 'active' );
					var f = $( this ).data( 'filter' );
					$( '#sentinel-open-issues-table tbody tr' ).each( function () {
						$( this ).toggle( f === 'all' || $( this ).data( 'severity' ) === f );
					} );
				} );

			} ).fail( function () {
				$btn.prop( 'disabled', false ).html( '⚠ View Open Issues' );
			} );
		} );

		// ── Scan Differential panel ────────────────────────────────────────────
		var diffData = null;

		$( '#sentinel-load-differential' ).on( 'click', function () {
			var $btn   = $( this ).prop( 'disabled', true ).text( 'Loading…' );
			var $panel = $( '#sentinel-diff-panel' );
			var nonce  = ( window.sentinelData && sentinelData.nonces ) ? sentinelData.nonces.scan : '';

			$.post( ajaxurl, {
				action: 'sentinel_get_scan_differential',
				nonce:  nonce
			}, function ( r ) {
				$btn.prop( 'disabled', false ).html( '📊 Compare Last Two Scans' );

				if ( ! r.success ) {
					var code = r.data && r.data.code;
					var msg  = r.data && r.data.message ? r.data.message : 'Error loading comparison.';
					$panel.show().find( '#sentinel-diff-summary' ).html(
						'<p style="color:' + ( 'insufficient_scans' === code ? '#b45309' : '#dc2626' ) + ';">' + msg + '</p>'
					);
					$panel.find( '#sentinel-diff-tabs, table' ).hide();
					return;
				}

				diffData = r.data;
				$panel.find( 'table' ).show();
				$panel.find( '#sentinel-diff-tabs' ).show();

				// Summary bar.
				var delta       = parseFloat( diffData.summary.score_delta || 0 );
				var deltaSign   = delta > 0 ? '+' : '';
				var deltaColor  = delta > 0 ? '#dc2626' : '#16a34a';
				var prevScan    = diffData.previous_scan;
				var latScan     = diffData.latest_scan;

				$( '#sentinel-diff-summary' ).html(
					'<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px;">' +
					[
						{ label: '🆕 New Issues',      value: diffData.summary.new,        color: diffData.summary.new > 0 ? '#dc2626' : '#16a34a' },
						{ label: '✅ Resolved',          value: diffData.summary.resolved,   color: diffData.summary.resolved > 0 ? '#16a34a' : '#94a3b8' },
						{ label: '⚠ Still Open',        value: diffData.summary.persisting, color: diffData.summary.persisting > 0 ? '#ea580c' : '#16a34a' },
						{ label: 'Risk Score Δ',        value: ( delta > 0 ? '+' : '' ) + delta.toFixed(1), color: deltaColor },
					].map( function ( k ) {
						return '<div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:14px;text-align:center;">' +
							'<div style="font-size:24px;font-weight:700;color:' + k.color + ';">' + k.value + '</div>' +
							'<div style="font-size:11px;color:#64748b;margin-top:3px;">' + k.label + '</div>' +
						'</div>';
					} ).join( '' ) +
					'</div>' +
					'<p style="font-size:12px;color:#64748b;margin:0 0 4px;">Comparing: ' +
					'<strong>' + ( latScan.scan_type.charAt(0).toUpperCase() + latScan.scan_type.slice(1) ) + '</strong> scan ' +
					'(' + latScan.completed_at.split(' ')[0] + ') vs. ' +
					'<strong>' + ( prevScan.scan_type.charAt(0).toUpperCase() + prevScan.scan_type.slice(1) ) + '</strong> scan ' +
					'(' + prevScan.completed_at.split(' ')[0] + ')</p>'
				);

				// Render with initial tab = new.
				renderDiffTab( 'new' );
				$panel.show();

				// Tab switching.
				$( '#sentinel-diff-tabs .sentinel-tab' ).on( 'click', function () {
					$( '#sentinel-diff-tabs .sentinel-tab' ).removeClass( 'active' );
					$( this ).addClass( 'active' );
					renderDiffTab( $( this ).data( 'diff' ) );
				} );

			} ).fail( function () {
				$btn.prop( 'disabled', false ).html( '📊 Compare Last Two Scans' );
			} );
		} );

		function renderDiffTab( tab ) {
			if ( ! diffData ) { return; }
			var items = diffData[ tab ] || [];

			if ( ! items.length ) {
				$( '#sentinel-diff-body' ).html(
					'<tr><td colspan="4" style="text-align:center;color:#94a3b8;">' +
					{ new: 'No new issues since the previous scan.', resolved: 'No issues were resolved.', persisting: 'No issues are persisting.' }[ tab ] +
					'</td></tr>'
				);
				return;
			}

			$( '#sentinel-diff-body' ).html( items.map( function ( v ) {
				return '<tr>' +
					'<td>' + severityBadge( v.severity ) + '</td>' +
					'<td><strong>' + $( '<span>' ).text( v.component_name ).html() + '</strong>' +
						( v.component_version ? ' <small style="color:#94a3b8;">v' + v.component_version + '</small>' : '' ) + '</td>' +
					'<td>' + $( '<span>' ).text( v.title ).html() +
						( v.vulnerability_id ? ' <span style="font-size:11px;color:#2563eb;background:#eff6ff;padding:1px 6px;border-radius:3px;">' + v.vulnerability_id + '</span>' : '' ) + '</td>' +
					'<td>' + ( v.cvss_score || '—' ) + '</td>' +
				'</tr>';
			} ).join( '' ) );
		}

	} );

} )( jQuery );
