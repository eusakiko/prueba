/**
 * WP Sentinel Security — Main Admin JS
 *
 * @package WP_Sentinel_Security
 */
/* global sentinelData, Chart */
( function ( $ ) {
	'use strict';

	var Sentinel = {

		currentScanId:    null,
		pollInterval:     null,
		POLL_INTERVAL_MS: 2000,

		init: function () {
			this.bindEvents();
			this.initCharts();
		},

		bindEvents: function () {
			$( document ).on( 'click', '.sentinel-start-scan',      this.startScan.bind( this ) );
			$( document ).on( 'click', '#sentinelCancelScan',       this.cancelScan.bind( this ) );
			$( document ).on( 'click', '.sentinel-create-backup',   this.createBackup.bind( this ) );
			$( document ).on( 'click', '.sentinel-restore-backup',  this.restoreBackup.bind( this ) );
			$( document ).on( 'click', '.sentinel-delete-backup',   this.deleteBackup.bind( this ) );
			$( document ).on( 'click', '.sentinel-vuln-details',    this.showVulnDetails.bind( this ) );
			$( document ).on( 'click', '.sentinel-tab',             this.filterResults.bind( this ) );
			$( document ).on( 'click', '.sentinel-load-scan',       this.loadPastScan.bind( this ) );
		$( document ).on( 'click', '.sentinel-vuln-mark',       this.onVulnMarkClick.bind( this ) );
		$( document ).on( 'click', '#sentinel-bulk-apply',      this.bulkMarkVulnerabilities.bind( this ) );
		$( document ).on( 'change', '#sentinel-select-all',     this.toggleSelectAll.bind( this ) );
		},

		// ---------------------------------------------------------------
		// Scan
		// ---------------------------------------------------------------

		startScan: function ( e ) {
			var $btn  = $( e.currentTarget );
			var type  = $btn.data( 'scan-type' ) || 'quick';
			var self  = this;

			$btn.prop( 'disabled', true );
			$( '.sentinel-start-scan' ).prop( 'disabled', true );
			this.showProgress( 5, sentinelData.i18n.scanning );

			// The scan runs synchronously server-side, so this AJAX call may
			// take a while. We animate progress while we wait.
			var fakeProgress = 5;
			var fakeTimer = setInterval( function () {
				fakeProgress = Math.min( 90, fakeProgress + Math.random() * 4 );
				self.showProgress( fakeProgress, sentinelData.i18n.scanning );
			}, 800 );

			$.ajax( {
				url:     sentinelData.ajaxUrl,
				method:  'POST',
				timeout: 300000, // 5 min max
				data:    {
					action:    'sentinel_start_scan',
					scan_type: type,
					nonce:     sentinelData.nonces.scan,
				},
				success: function ( response ) {
					clearInterval( fakeTimer );
					if ( response.success && response.data.scan_id ) {
						self.currentScanId = response.data.scan_id;
						// Scan is already done — just poll once to get results.
						self.pollScanProgress();
					} else {
						self.hideProgress();
						self.showNotification( ( response.data && response.data.message ) || sentinelData.i18n.scanFailed, 'error' );
						$( '.sentinel-start-scan' ).prop( 'disabled', false );
					}
				},
				error: function () {
					clearInterval( fakeTimer );
					self.hideProgress();
					self.showNotification( sentinelData.i18n.scanFailed, 'error' );
					$( '.sentinel-start-scan' ).prop( 'disabled', false );
				},
			} );
		},

		pollScanProgress: function () {
			var self = this;

			$.ajax( {
				url:    sentinelData.ajaxUrl,
				method: 'POST',
				data:   {
					action:  'sentinel_scan_progress',
					scan_id: self.currentScanId,
					nonce:   sentinelData.nonces.scan,
				},
				success: function ( response ) {
					if ( ! response.success ) { return; }

					var d = response.data;
					self.showProgress( d.progress || 0, d.status_text || sentinelData.i18n.scanning );

					if ( 'completed' === d.status || 'failed' === d.status || 'cancelled' === d.status ) {
						self.onScanComplete( d );
					} else {
						// Still running — keep polling.
						if ( self.pollInterval ) { clearInterval( self.pollInterval ); }
						self.pollInterval = setInterval( self.pollScanProgress.bind( self ), self.POLL_INTERVAL_MS );
					}
				},
			} );
		},

		onScanComplete: function ( data ) {
			if ( this.pollInterval ) {
				clearInterval( this.pollInterval );
				this.pollInterval = null;
			}
			this.currentScanId = null;
			this.hideProgress();
			$( '.sentinel-start-scan' ).prop( 'disabled', false );

			if ( 'completed' === data.status ) {
				this.showNotification( sentinelData.i18n.scanComplete, 'success', sentinelData.i18n.scanCompleteNext );
				this.renderScanResults( data.vulnerabilities || [], null );
				$( '#sentinel-scan-results' ).show();
				$( 'html, body' ).animate( { scrollTop: $( '#sentinel-scan-results' ).offset().top - 40 }, 400 );
			} else {
				this.showNotification( sentinelData.i18n.scanFailed, 'error' );
			}
		},

		cancelScan: function () {
			if ( ! this.currentScanId ) { return; }

			$.ajax( {
				url:    sentinelData.ajaxUrl,
				method: 'POST',
				data:   {
					action:  'sentinel_cancel_scan',
					scan_id: this.currentScanId,
					nonce:   sentinelData.nonces.scan,
				},
			} );

			if ( this.pollInterval ) { clearInterval( this.pollInterval ); }
			this.pollInterval  = null;
			this.currentScanId = null;
			this.hideProgress();
			$( '.sentinel-start-scan' ).prop( 'disabled', false );
		},

		// ---------------------------------------------------------------
		// Load past scan results
		// ---------------------------------------------------------------

		loadPastScan: function ( e ) {
			var $btn   = $( e.currentTarget );
			var scanId = $btn.data( 'id' );
			var self   = this;

			$btn.prop( 'disabled', true ).text( '...' );

			$.ajax( {
				url:    sentinelData.ajaxUrl,
				method: 'POST',
				data:   {
					action:  'sentinel_load_scan_results',
					scan_id: scanId,
					nonce:   sentinelData.nonces.scan,
				},
				success: function ( response ) {
					$btn.prop( 'disabled', false ).text( sentinelData.i18n.viewResults );
					if ( response.success ) {
						self.renderScanResults( response.data.vulnerabilities || [], response.data.scan );
						$( '#sentinel-scan-results' ).show();
						$( 'html, body' ).animate( { scrollTop: $( '#sentinel-scan-results' ).offset().top - 40 }, 400 );
					}
				},
				error: function () {
					$btn.prop( 'disabled', false ).text( sentinelData.i18n.viewResults );
				},
			} );
		},

		// ---------------------------------------------------------------
		// Render results
		// ---------------------------------------------------------------

		renderScanResults: function ( vulnerabilities, scan ) {
			var $results = $( '#sentinel-scan-results' );
			var $body    = $( '#sentinelResultsBody' );
			$body.empty();

			// Update results header with scan info.
			if ( scan ) {
				$( '#sentinel-results-scan-info' ).text(
					sentinelData.i18n.scanType + ': ' + scan.scan_type +
					'  |  ' + sentinelData.i18n.scanDate + ': ' + scan.started_at +
					'  |  ' + sentinelData.i18n.issuesFound + ': ' + ( scan.vulnerabilities_found || 0 )
				).show();
			} else {
				$( '#sentinel-results-scan-info' ).hide();
			}

			if ( ! vulnerabilities.length ) {
				$body.html( '<tr><td colspan="6">' + sentinelData.i18n.noVulnerabilities + '</td></tr>' );
				return;
			}

			var urgencyMap = {
				critical: sentinelData.i18n.urgencyCritical,
				high:     sentinelData.i18n.urgencyHigh,
				medium:   sentinelData.i18n.urgencyMedium,
				low:      sentinelData.i18n.urgencyLow,
				info:     sentinelData.i18n.urgencyInfo,
			};

			$.each( vulnerabilities, function ( i, v ) {
				var sev     = v.severity || 'info';
				var urgency = urgencyMap[ sev ] || sev;
				var compType = v.component_type || '';
				var ctaHtml;
				var isOpen = ! v.status || 'open' === v.status;

				// Fix button.
				if ( 'plugin' === compType || 'theme' === compType ) {
					ctaHtml = '<a href="' + sentinelData.updateUrl + '" class="button button-small button-primary">' +
						sentinelData.i18n.fixNow + '</a> ';
				} else {
					ctaHtml = '<a href="' + sentinelData.hardeningUrl + '" class="button button-small button-primary">' +
						sentinelData.i18n.fixNow + '</a> ';
				}

				var vid = parseInt( v.id, 10 ) || 0;
				ctaHtml += '<button class="button button-small sentinel-vuln-details" data-id="' + vid + '">' +
					sentinelData.i18n.viewGuide + '</button> ';

				// Ignore / FP / Reopen buttons (only when vuln has a DB id).
				if ( vid ) {
					ctaHtml += '<button class="button button-small sentinel-vuln-mark" data-id="' + vid + '" data-action="ignored"' +
						( ! isOpen ? ' style="display:none"' : '' ) + '>' +
						( sentinelData.i18n.ignore || 'Ignore' ) + '</button> ';
					ctaHtml += '<button class="button button-small sentinel-vuln-mark" data-id="' + vid + '" data-action="false_positive"' +
						( ! isOpen ? ' style="display:none"' : '' ) + '>' +
						( sentinelData.i18n.markFp || 'False positive' ) + '</button> ';
					ctaHtml += '<button class="button button-small sentinel-vuln-mark" data-id="' + vid + '" data-action="open"' +
						( isOpen ? ' style="display:none"' : '' ) + '>' +
						( sentinelData.i18n.reopen || 'Reopen' ) + '</button>';
				}

				// CVE link to NVD.
				var vulnIdHtml = '';
				if ( v.vulnerability_id ) {
					var vid = $( '<span>' ).text( v.vulnerability_id ).html();
					if ( /^CVE-\d{4}-\d+$/i.test( v.vulnerability_id ) ) {
						vulnIdHtml = ' <a href="https://nvd.nist.gov/vuln/detail/' + vid + '" target="_blank" rel="noopener noreferrer" ' +
							'title="' + sentinelData.i18n.viewCve + '" class="sentinel-cve-link">' + vid + ' ↗</a>';
					}
				}

				var titleEsc = $( '<span>' ).text( v.title ).html();
				var rowStyle = ( ! isOpen ) ? ' style="opacity:0.45"' : '';
				var row = '<tr data-severity="' + $( '<span>' ).text( sev ).html() + '"' + rowStyle + '>' +
					'<td style="width:32px;"><input type="checkbox" class="sentinel-vuln-checkbox" value="' + ( parseInt( v.id, 10 ) || 0 ) + '"></td>' +
					'<td>' +
						'<span class="sentinel-badge sentinel-badge-' + sev + '">' + sev.toUpperCase() + '</span>' +
						'<div class="sentinel-urgency-label">' + $( '<span>' ).text( urgency ).html() + '</div>' +
					'</td>' +
					'<td>' + $( '<span>' ).text( v.component_name || '' ).html() +
						( v.component_version ? ' <small style="color:#94a3b8">v' + $( '<span>' ).text( v.component_version ).html() + '</small>' : '' ) +
					'</td>' +
					'<td>' + titleEsc + vulnIdHtml + '</td>' +
					'<td><strong>' + $( '<span>' ).text( v.cvss_score || '—' ).html() + '</strong></td>' +
					'<td class="sentinel-finding-actions">' + ctaHtml + '</td>' +
					'</tr>';

				$body.append( row );
			} );

			// Reset active filter.
			$( '.sentinel-tab' ).removeClass( 'active' );
			$( '.sentinel-tab[data-filter="all"]' ).addClass( 'active' );
		},

		// ---------------------------------------------------------------
		// Filter results by severity
		// ---------------------------------------------------------------

		filterResults: function ( e ) {
			var $btn    = $( e.currentTarget );
			var filter  = $btn.data( 'filter' );

			$( '.sentinel-tab' ).removeClass( 'active' );
			$btn.addClass( 'active' );

			if ( 'all' === filter ) {
				$( '#sentinelResultsBody tr' ).show();
			} else {
				$( '#sentinelResultsBody tr' ).hide();
				$( '#sentinelResultsBody tr[data-severity="' + filter + '"]' ).show();
			}
		},

		// ---------------------------------------------------------------
		// Vulnerability detail modal
		// ---------------------------------------------------------------

		onVulnMarkClick: function ( e ) {
			var $btn   = $( e.currentTarget );
			var vulnId = parseInt( $btn.data( 'id' ), 10 );
			var action = $btn.data( 'action' );
			var $row   = $btn.closest( 'tr' );
			this.markVulnerability( vulnId, action, $row );
		},

		toggleSelectAll: function ( e ) {
			var checked = $( e.currentTarget ).is( ':checked' );
			$( '#sentinelResultsBody .sentinel-vuln-checkbox:visible' ).prop( 'checked', checked );
		},

		showVulnDetails: function ( e ) {
			var vulnId = parseInt( $( e.currentTarget ).data( 'id' ), 10 );
			if ( ! vulnId ) { return; }

			var self = this;

			// Show loading modal immediately.
			var $modal = $( '<div class="sentinel-modal-overlay">' +
				'<div class="sentinel-modal sentinel-modal-loading">' +
					'<button class="sentinel-modal-close">&times;</button>' +
					'<p style="color:#64748b;text-align:center;padding:32px 0;">' + ( sentinelData.i18n.loading || 'Loading...' ) + '</p>' +
				'</div>' +
			'</div>' );
			$( 'body' ).append( $modal );
			$modal.on( 'click', function ( ev ) {
				if ( $( ev.target ).is( '.sentinel-modal-overlay' ) || $( ev.target ).is( '.sentinel-modal-close' ) ) {
					$modal.remove();
				}
			} );

			$.ajax( {
				url:    sentinelData.ajaxUrl,
				method: 'POST',
				data:   { action: 'sentinel_get_vulnerability', vuln_id: vulnId, nonce: sentinelData.nonces.scan },
				success: function ( response ) {
					if ( ! response.success || ! response.data.vulnerability ) {
						$modal.find( '.sentinel-modal' ).html( '<button class="sentinel-modal-close">&times;</button><p style="color:#dc2626;text-align:center;padding:24px;">' + sentinelData.i18n.detailsUnavailable + '</p>' );
						return;
					}
					var v   = response.data.vulnerability;
					var sev = v.severity || 'info';

					var sevColors = { critical: '#dc2626', high: '#ea580c', medium: '#ca8a04', low: '#16a34a', info: '#2563eb' };
					var sevColor  = sevColors[ sev ] || '#64748b';

					var refsHtml = '';
					if ( v.reference_urls_array && v.reference_urls_array.length ) {
						refsHtml = '<div style="margin-top:12px;"><strong>' + ( sentinelData.i18n.references || 'References' ) + '</strong><ul style="margin:6px 0 0 18px;">';
						$.each( v.reference_urls_array, function ( i, url ) {
							refsHtml += '<li><a href="' + $( '<span>' ).text( url ).html() + '" target="_blank" rel="noopener noreferrer">' +
								$( '<span>' ).text( url ).html() + '</a></li>';
						} );
						refsHtml += '</ul></div>';
					}

					var cvssHtml = v.cvss_score && parseFloat( v.cvss_score ) > 0
						? '<span style="font-weight:700;font-size:18px;color:' + sevColor + ';">' + v.cvss_score + '</span> <span style="color:#94a3b8;font-size:12px;">CVSS</span>'
						: '';

					var cveLink = /^CVE-\d{4}-\d+$/i.test( v.vulnerability_id )
						? ' &nbsp;<a href="https://nvd.nist.gov/vuln/detail/' + v.vulnerability_id + '" target="_blank" rel="noopener noreferrer" class="sentinel-cve-link">' + v.vulnerability_id + ' ↗</a>'
						: '';

					var statusBadge = '';
					if ( 'ignored' === v.status ) { statusBadge = '<span style="background:#fef3c7;color:#92400e;font-size:11px;font-weight:600;padding:2px 8px;border-radius:99px;margin-left:8px;">IGNORED</span>'; }
					else if ( 'false_positive' === v.status ) { statusBadge = '<span style="background:#f0f9ff;color:#0369a1;font-size:11px;font-weight:600;padding:2px 8px;border-radius:99px;margin-left:8px;">FALSE POSITIVE</span>'; }

					var html =
						'<button class="sentinel-modal-close">&times;</button>' +
						'<div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:16px;">' +
							'<h3 style="margin:0;flex:1;">' + $( '<span>' ).text( v.title ).html() + cveLink + statusBadge + '</h3>' +
							( cvssHtml ? '<div style="text-align:right;flex-shrink:0;">' + cvssHtml + '</div>' : '' ) +
						'</div>' +
						'<div style="margin-bottom:12px;">' +
							'<span class="sentinel-badge sentinel-badge-' + sev + '">' + sev.toUpperCase() + '</span>' +
							'&nbsp;<span style="color:#64748b;font-size:12px;">' + $( '<span>' ).text( v.component_name || '' ).html() +
								( v.component_version ? ' v' + v.component_version : '' ) + '</span>' +
						'</div>' +
						'<div style="background:#f8fafc;border-radius:8px;padding:12px 16px;margin-bottom:12px;font-size:13px;color:#334155;line-height:1.6;">' +
							'<strong>' + sentinelData.i18n.whatThisMeans + '</strong><br>' +
							$( '<span>' ).text( v.description ).html().replace( /\n/g, '<br>' ) +
						'</div>' +
						( v.recommendation ? '<div style="background:#f0fdf4;border-left:4px solid #16a34a;border-radius:0 8px 8px 0;padding:12px 16px;margin-bottom:12px;font-size:13px;color:#166534;line-height:1.6;">' +
							'<strong>' + sentinelData.i18n.whatToDoNext + '</strong><br>' +
							$( '<span>' ).text( v.recommendation ).html().replace( /\n/g, '<br>' ) +
						'</div>' : '' ) +
						refsHtml +
						'<div style="margin-top:16px;padding-top:12px;border-top:1px solid #f1f5f9;display:flex;gap:8px;flex-wrap:wrap;">' +
							( 'open' === v.status
								? '<button class="button button-secondary sentinel-modal-ignore" data-id="' + v.id + '" data-action="ignored">' + ( sentinelData.i18n.ignore || 'Ignore' ) + '</button>' +
								  '<button class="button button-secondary sentinel-modal-ignore" data-id="' + v.id + '" data-action="false_positive">' + ( sentinelData.i18n.markFp || 'Mark as false positive' ) + '</button>'
								: '<button class="button button-secondary sentinel-modal-ignore" data-id="' + v.id + '" data-action="open">' + ( sentinelData.i18n.reopen || 'Reopen' ) + '</button>'
							) +
						'</div>';

					$modal.find( '.sentinel-modal' ).html( html ).removeClass( 'sentinel-modal-loading' );

					// Modal-level ignore/FP buttons.
					$modal.on( 'click', '.sentinel-modal-ignore', function () {
						var btnId = parseInt( $( this ).data( 'id' ), 10 );
						var btnAction = $( this ).data( 'action' );
						var $tableRow = $( '#sentinelResultsBody .sentinel-vuln-details[data-id="' + btnId + '"]' ).closest( 'tr' );
						self.markVulnerability( btnId, btnAction, $tableRow.length ? $tableRow : $( '<tr>' ) );
						$modal.remove();
					} );
				},
				error: function () {
					$modal.remove();
					self.showNotification( sentinelData.i18n.actionFailed || 'Error loading details.', 'error' );
				},
			} );
		},

		// ---------------------------------------------------------------
		// Backup
		// ---------------------------------------------------------------

		createBackup: function () {
			var self = this;
			this.showNotification( sentinelData.i18n.backupCreating, 'info' );

			$.ajax( {
				url:     sentinelData.ajaxUrl,
				method:  'POST',
				timeout: 120000,
				data:    {
					action: 'sentinel_create_backup',
					nonce:  sentinelData.nonces.backup,
				},
				success: function ( response ) {
					if ( response.success ) {
						self.showNotification( sentinelData.i18n.backupComplete, 'success', sentinelData.i18n.backupCompleteNext );
					} else {
						self.showNotification( ( response.data && response.data.message ) || sentinelData.i18n.backupFailed, 'error' );
					}
				},
				error: function () {
					self.showNotification( sentinelData.i18n.backupFailed, 'error' );
				},
			} );
		},

		restoreBackup: function ( e ) {
			if ( ! window.confirm( sentinelData.i18n.confirmRestore ) ) { return; } // phpcs:ignore
			var backupId = $( e.currentTarget ).data( 'id' );
			$.ajax( {
				url:    sentinelData.ajaxUrl,
				method: 'POST',
				data:   { action: 'sentinel_restore_backup', backup_id: parseInt( backupId, 10 ), nonce: sentinelData.nonces.restore },
			} );
		},

		deleteBackup: function ( e ) {
			if ( ! window.confirm( sentinelData.i18n.confirmDelete ) ) { return; } // phpcs:ignore
			var backupId = $( e.currentTarget ).data( 'id' );
			var self     = this;

			$.ajax( {
				url:    sentinelData.ajaxUrl,
				method: 'POST',
				data:   { action: 'sentinel_delete_backup', backup_id: parseInt( backupId, 10 ), nonce: sentinelData.nonces.delete },
				success: function ( response ) {
					if ( response.success ) {
						self.showNotification( sentinelData.i18n.backupDeleted || 'Backup deleted.', 'success' );
						$( e.currentTarget ).closest( 'tr' ).fadeOut();
					}
				},
			} );
		},

		// ---------------------------------------------------------------
		// Charts
		// ---------------------------------------------------------------

		initCharts: function () {
			if ( typeof Chart === 'undefined' ) { return; }

			var scoreCtx = document.getElementById( 'sentinelScoreChart' );
			var vulnCtx  = document.getElementById( 'sentinelVulnChart' );

			// ── Security Score Evolution ──────────────────────────────────────
			if ( scoreCtx ) {
				var history = ( sentinelData.scoreHistory && sentinelData.scoreHistory.length )
					? sentinelData.scoreHistory : null;

				if ( ! history ) {
					// Empty state — draw a "no data" placeholder.
					scoreCtx.parentElement.innerHTML =
						'<div style="display:flex;flex-direction:column;align-items:center;justify-content:center;' +
						'height:180px;color:#94a3b8;gap:8px;">' +
						'<span class="dashicons dashicons-chart-line" style="font-size:36px;width:36px;height:36px;"></span>' +
						'<span style="font-size:13px;">Run a scan to start tracking your security score over time.</span>' +
						'</div>';
				} else {
					new Chart( scoreCtx, {
						type: 'line',
						data: {
							labels:   history.map( function (d) { return d.date; } ),
							datasets: [
								{
									label:           ( sentinelData.i18n.securityScore || 'Risk Score' ),
									data:            history.map( function (d) { return parseFloat( d.avg_score ); } ),
									borderColor:     '#4f46e5',
									backgroundColor: 'rgba(79,70,229,.08)',
									tension:         0.4,
									fill:            true,
									yAxisID:         'yScore',
									pointRadius:     3,
									pointHoverRadius: 5,
								},
								{
									label:           'Vulnerabilities',
									data:            history.map( function (d) { return parseInt( d.total_vulns, 10 ); } ),
									borderColor:     '#dc2626',
									backgroundColor: 'rgba(220,38,38,.06)',
									tension:         0.3,
									fill:            false,
									yAxisID:         'yVulns',
									borderDash:      [ 4, 3 ],
									pointRadius:     2,
									pointHoverRadius: 4,
								},
							],
						},
						options: {
							responsive:          true,
							maintainAspectRatio: true,
							interaction: { mode: 'index', intersect: false },
							scales: {
								yScore: {
									type:     'linear',
									position: 'left',
									min:      0,
									max:      100,
									title:    { display: true, text: 'Risk Score' },
									grid:     { color: 'rgba(0,0,0,.05)' },
								},
								yVulns: {
									type:       'linear',
									position:   'right',
									min:        0,
									title:      { display: true, text: 'Vulns' },
									grid:       { drawOnChartArea: false },
								},
							},
							plugins: {
								legend: { position: 'bottom', labels: { boxWidth: 14, padding: 16 } },
								tooltip: {
									callbacks: {
										title: function( items ) { return items[0].label; },
									},
								},
							},
						},
					} );
				}
			}

			// ── Vulnerability Breakdown Doughnut ──────────────────────────────
			if ( vulnCtx && sentinelData.vulnCounts ) {
				var vc = sentinelData.vulnCounts;
				var total = ( vc.critical || 0 ) + ( vc.high || 0 ) + ( vc.medium || 0 ) + ( vc.low || 0 ) + ( vc.info || 0 );

				if ( ! total ) {
					vulnCtx.parentElement.innerHTML =
						'<div style="display:flex;flex-direction:column;align-items:center;justify-content:center;' +
						'height:200px;color:#16a34a;gap:8px;">' +
						'<span class="dashicons dashicons-yes-alt" style="font-size:44px;width:44px;height:44px;"></span>' +
						'<span style="font-size:14px;font-weight:600;">No open vulnerabilities</span>' +
						'</div>';
				} else {
					new Chart( vulnCtx, {
						type: 'doughnut',
						data: {
							labels:   [
								sentinelData.i18n.urgencyCritical || 'Critical',
								sentinelData.i18n.urgencyHigh     || 'High',
								sentinelData.i18n.urgencyMedium   || 'Medium',
								sentinelData.i18n.urgencyLow      || 'Low',
								sentinelData.i18n.urgencyInfo     || 'Info',
							],
							datasets: [ {
								data:            [ vc.critical || 0, vc.high || 0, vc.medium || 0, vc.low || 0, vc.info || 0 ],
								backgroundColor: [ '#dc2626', '#ea580c', '#ca8a04', '#16a34a', '#2563eb' ],
								borderWidth:     2,
								hoverOffset:     6,
							} ],
						},
						options: {
							responsive: true,
							cutout:     '68%',
							plugins: {
								legend: { position: 'bottom', labels: { boxWidth: 12, padding: 12, font: { size: 11 } } },
								tooltip: {
									callbacks: {
										label: function( ctx ) {
											var pct = Math.round( ctx.parsed / total * 100 );
											return ' ' + ctx.label + ': ' + ctx.parsed + ' (' + pct + '%)';
										},
									},
								},
							},
						},
					} );
				}
			}
		},

		// ---------------------------------------------------------------
		// UI Helpers
		// ---------------------------------------------------------------

		showProgress: function ( pct, status ) {
			$( '#sentinel-scan-progress' ).show();
			$( '#sentinelProgressFill' ).css( 'width', Math.min( 100, pct ) + '%' );
			$( '#sentinelProgressText' ).text( Math.min( 100, Math.round( pct ) ) + '%' );
			$( '#sentinelProgressStatus' ).text( status || '' );
		},

		hideProgress: function () {
			$( '#sentinel-scan-progress' ).hide();
		},

		// ---------------------------------------------------------------
		// Vulnerability bulk mark helpers (must appear before showNotification)
		// ---------------------------------------------------------------

		markVulnerability: function ( vulnId, action, $row ) {
			var self  = this;
			var $btns = $row.find( '.sentinel-vuln-mark, .sentinel-modal-ignore' );
			$btns.prop( 'disabled', true );

			$.ajax( {
				url:    sentinelData.ajaxUrl,
				method: 'POST',
				data:   {
					action:      'sentinel_mark_vulnerability',
					vuln_id:     vulnId,
					vuln_action: action,
					nonce:       sentinelData.nonces.scan,
				},
				success: function ( response ) {
					if ( response.success ) {
						if ( 'open' === action ) {
							$row.css( 'opacity', '' );
							$row.find( '.sentinel-status-label' ).remove();
							$row.find( '[data-action="ignored"],[data-action="false_positive"]' ).show();
							$row.find( '[data-action="open"]' ).hide();
						} else {
							$row.css( 'opacity', '0.45' );
							var lbl = 'ignored' === action
								? ( sentinelData.i18n.markedIgnored || 'Ignored' )
								: ( sentinelData.i18n.markedFp || 'False positive' );
							$row.find( '.sentinel-status-label' ).remove();
							$row.find( 'td:last-child' ).prepend(
								'<span class="sentinel-status-label" style="font-size:11px;color:#64748b;margin-right:6px;">' + lbl + '</span>'
							);
							$row.find( '[data-action="ignored"],[data-action="false_positive"]' ).hide();
							$row.find( '[data-action="open"]' ).show();
						}
						self.showNotification( response.data.message || sentinelData.i18n.statusUpdated || 'Updated.', 'success' );
					} else {
						self.showNotification( ( response.data && response.data.message ) || sentinelData.i18n.actionFailed || 'Error.', 'error' );
						$btns.prop( 'disabled', false );
					}
				},
				error: function () {
					self.showNotification( sentinelData.i18n.actionFailed || 'Error.', 'error' );
					$btns.prop( 'disabled', false );
				},
			} );
		},

		bulkMarkVulnerabilities: function () {
			var action = $( '#sentinel-bulk-action' ).val();
			if ( ! action ) {
				this.showNotification( sentinelData.i18n.selectAction || 'Select an action first.', 'error' );
				return;
			}
			var ids = [];
			$( '.sentinel-vuln-checkbox:checked' ).each( function () {
				var idVal = parseInt( $( this ).val(), 10 );
				if ( idVal ) { ids.push( idVal ); }
			} );
			if ( ! ids.length ) {
				this.showNotification( sentinelData.i18n.selectItems || 'Select at least one item.', 'error' );
				return;
			}
			var self = this;
			$.ajax( {
				url:    sentinelData.ajaxUrl,
				method: 'POST',
				data:   {
					action:      'sentinel_bulk_mark_vulnerability',
					vuln_ids:    ids,
					vuln_action: action,
					nonce:       sentinelData.nonces.scan,
				},
				success: function ( r ) {
					if ( r.success ) {
						self.showNotification( r.data.message, 'success' );
						$( '.sentinel-vuln-checkbox:checked' ).each( function () {
							$( this ).closest( 'tr' ).css( 'opacity', 'open' !== action ? '0.45' : '' );
							$( this ).prop( 'checked', false );
						} );
						$( '#sentinel-select-all' ).prop( 'checked', false );
					} else {
						self.showNotification( ( r.data && r.data.message ) || 'Error.', 'error' );
					}
				},
				error: function () { self.showNotification( sentinelData.i18n.actionFailed || 'Error.', 'error' ); },
			} );
		},

		onVulnMarkClick: function ( e ) {
			var $btn   = $( e.currentTarget );
			var vulnId = parseInt( $btn.data( 'id' ), 10 );
			var action = $btn.data( 'action' );
			var $row   = $btn.closest( 'tr' );
			this.markVulnerability( vulnId, action, $row );
		},

		toggleSelectAll: function ( e ) {
			var checked = $( e.currentTarget ).is( ':checked' );
			$( '#sentinelResultsBody .sentinel-vuln-checkbox' ).filter( ':visible' ).prop( 'checked', checked );
		},

		showNotification: function ( message, type, nextStep ) {
			type = type || 'info';
			var html = $( '<span>' ).text( message ).html();
			if ( nextStep ) {
				html += '<div class="sentinel-notification-next">' + $( '<span>' ).text( nextStep ).html() + '</div>';
			}
			var $note = $( '<div class="sentinel-notification sentinel-notification-' + type + '">' + html + '</div>' );
			$( 'body' ).append( $note );
			setTimeout( function () {
				$note.fadeOut( 400, function () { $( this ).remove(); } );
			}, 8000 );
		},
	};

	$( function () {
		Sentinel.init();
	} );

} )( jQuery );
