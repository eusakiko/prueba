/**
 * Intelligence page AJAX handlers.
 *
 * Handles the "Run Analysis" button and results display
 * on the Sentinel Intelligence admin page.
 *
 * @package WP_Sentinel_Security
 */

/* global sentinelData, jQuery */

jQuery( function ( $ ) {
	'use strict';

	var $btn     = $( '#sentinel-run-analysis' );
	var $results = $( '#sentinel-analysis-results' );

	if ( ! $btn.length ) {
		return;
	}

	$btn.on( 'click', function () {
		var originalText = $btn.text();

		// Loading state.
		$btn.prop( 'disabled', true ).text(
			$btn.data( 'loading-text' ) || 'Analysing…'
		);
		$results.hide().empty();

		$.ajax( {
			url:    sentinelData.ajaxUrl,
			method: 'POST',
			data:   {
				action: 'sentinel_run_intelligence',
				nonce:  sentinelData.nonces.intelligence
			},
			success: function ( response ) {
				if ( response.success && response.data ) {
					// Reload the page so the Blacklist Monitor section and all other
					// Intelligence widgets reflect the freshly-computed data.
					// A brief status message is shown first so the admin sees feedback.
					$btn.prop( 'disabled', true ).text( '✓ Analysis complete — reloading…' );
					setTimeout( function () { location.reload(); }, 800 );
				} else {
					var msg = ( response.data && response.data.message )
						? response.data.message
						: 'Intelligence analysis failed. Please try again.';
					renderError( msg );
				}
			},
			error: function ( jqXHR, textStatus ) {
				renderError( 'Request failed (' + textStatus + '). Please check your connection and try again.' );
			},
			complete: function () {
				$btn.prop( 'disabled', false ).text( originalText );
			}
		} );
	} );

	/**
	 * Render analysis results in the results container.
	 *
	 * @param {Object} data Response data from the server.
	 */
	function renderResults( data ) {
		var html = '<div class="sentinel-card" style="margin-top:0;">';

		if ( data.summary ) {
			html += '<h3 style="margin-bottom:12px;">Analysis Summary</h3>';
			html += '<p>' + escapeHtml( String( data.summary ) ) + '</p>';
		}

		if ( data.recommendations && data.recommendations.length ) {
			html += '<h3 style="margin:16px 0 8px;">Recommendations</h3><ul style="margin:0 0 0 20px;">';
			data.recommendations.forEach( function ( rec ) {
				html += '<li style="margin-bottom:6px;">' + escapeHtml( String( rec ) ) + '</li>';
			} );
			html += '</ul>';
		}

		if ( data.risk_score !== undefined ) {
			html += '<p style="margin-top:16px;"><strong>Risk Score:</strong> ' + escapeHtml( String( data.risk_score ) ) + '</p>';
		}

		html += '</div>';

		$results.html( html ).slideDown( 200 );
	}

	/**
	 * Render an error message.
	 *
	 * @param {string} message Error message to display.
	 */
	function renderError( message ) {
		$results
			.html(
				'<div class="notice notice-error" style="margin:0;"><p>' + escapeHtml( message ) + '</p></div>'
			)
			.slideDown( 200 );
	}

	/**
	 * Escape HTML entities to prevent XSS.
	 *
	 * @param {string} str Raw string.
	 * @return {string}    Escaped string.
	 */
	function escapeHtml( str ) {
		return str
			.replace( /&/g, '&amp;' )
			.replace( /</g, '&lt;' )
			.replace( />/g, '&gt;' )
			.replace( /"/g, '&quot;' )
			.replace( /'/g, '&#039;' );
	}
} );
