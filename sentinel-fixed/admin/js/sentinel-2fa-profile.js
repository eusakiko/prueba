/**
 * Sentinel Security — 2FA Profile Setup Wizard
 *
 * Drives the multi-step AJAX setup flow on wp-admin/profile.php:
 *   Step 1 – User clicks "Set up 2FA"
 *   Step 2 – Server returns secret + QR code; user scans and enters code
 *   Step 3 – Code verified; recovery codes displayed
 *   Step 4 – User confirms codes saved; UI resets to "Enabled"
 *
 * Also handles the "Disable 2FA" flow with a confirmation dialog.
 *
 * @package WP_Sentinel_Security
 * @since   2.3.0
 */
(function ($) {
	'use strict';

	var i18n    = sentinel2fa.i18n;
	var ajaxUrl = sentinel2fa.ajaxUrl;
	var nonce   = sentinel2fa.nonce;

	// ── Helpers ───────────────────────────────────────────────────────────────

	function wizardEl() {
		return $('#sentinel-2fa-wizard');
	}

	function notice(msg, type) {
		type = type || 'error';
		return $('<div class="notice notice-' + type + ' inline" style="margin-top:12px;"><p>' + msg + '</p></div>');
	}

	function cardHtml(html) {
		return '<div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:20px;">' + html + '</div>';
	}

	// ── Step 1 — Request secret from server ───────────────────────────────────

	$('#sentinel-2fa-setup-btn').on('click', function () {
		var userId  = $(this).data('user');
		var $btn    = $(this);
		var $wizard = wizardEl().show();

		$btn.prop('disabled', true).text('Loading…');
		$wizard.html('<p style="color:#888;">Generating secure secret…</p>');

		$.post(ajaxUrl, {
			action:  'sentinel_2fa_get_setup',
			nonce:   nonce,
			user_id: userId
		}, function (r) {
			$btn.prop('disabled', false).text('Set up 2FA');

			if (!r.success) {
				$wizard.html('').append(notice(r.data.message));
				return;
			}

			renderStep2($wizard, userId, r.data);
		}).fail(function () {
			$btn.prop('disabled', false).text('Set up 2FA');
			$wizard.html('').append(notice('Request failed. Please try again.'));
		});
	});

	// ── Step 2 — QR code + code input ─────────────────────────────────────────

	function renderStep2($wizard, userId, data) {
		var html =
			'<h3 style="margin-top:0;">' + i18n.setupTitle + '</h3>' +
			'<p>' + i18n.scanQr + '</p>' +
			'<div style="text-align:center;margin:12px 0;">' +
				'<div style="line-height:0;border:4px solid #fff;box-shadow:0 1px 4px rgba(0,0,0,.12);display:inline-block;">' + ( data.qr_svg || '' ) + '</div>' +
			'</div>' +
			'<p>' + i18n.manualEntry + '</p>' +
			'<p style="font-family:monospace;font-size:15px;background:#fff;padding:8px 12px;border:1px solid #e2e8f0;border-radius:4px;word-break:break-all;letter-spacing:2px;">' +
				data.secret +
			'</p>' +
			'<p style="margin-top:16px;">' + i18n.enterCode + '</p>' +
			'<div style="display:flex;gap:8px;align-items:center;">' +
				'<input type="text" id="sentinel-2fa-code-input" ' +
					'style="font-size:20px;letter-spacing:4px;text-align:center;width:140px;" ' +
					'maxlength="6" inputmode="numeric" placeholder="000000" autocomplete="one-time-code">' +
				'<button type="button" id="sentinel-2fa-confirm-btn" class="button button-primary">' +
					i18n.confirm +
				'</button>' +
			'</div>' +
			'<div id="sentinel-2fa-step2-notice"></div>';

		$wizard.html(cardHtml(html));

		// Auto-focus code input.
		$('#sentinel-2fa-code-input').trigger('focus');

		// Allow submitting with Enter key.
		$('#sentinel-2fa-code-input').on('keydown', function (e) {
			if (e.key === 'Enter') {
				$('#sentinel-2fa-confirm-btn').trigger('click');
			}
		});

		$('#sentinel-2fa-confirm-btn').on('click', function () {
			var code = $.trim($('#sentinel-2fa-code-input').val());
			if (code.length !== 6 || !/^\d{6}$/.test(code)) {
				$('#sentinel-2fa-step2-notice').html('').append(
					notice('Please enter a 6-digit numeric code.')
				);
				return;
			}

			var $btn = $(this).prop('disabled', true).text(i18n.saving);

			$.post(ajaxUrl, {
				action:  'sentinel_2fa_confirm_setup',
				nonce:   nonce,
				user_id: userId,
				code:    code
			}, function (r) {
				$btn.prop('disabled', false).text(i18n.confirm);

				if (!r.success) {
					$('#sentinel-2fa-step2-notice').html('').append(notice(r.data.message));
					$('#sentinel-2fa-code-input').val('').trigger('focus');
					return;
				}

				renderStep3($wizard, r.data.recovery_codes);
			}).fail(function () {
				$btn.prop('disabled', false).text(i18n.confirm);
				$('#sentinel-2fa-step2-notice').html('').append(notice('Request failed. Please try again.'));
			});
		});
	}

	// ── Step 3 — Recovery codes ────────────────────────────────────────────────

	function renderStep3($wizard, codes) {
		var codesHtml = codes.map(function (c) {
			return '<code style="display:inline-block;background:#fff;border:1px solid #e2e8f0;' +
				'border-radius:4px;padding:4px 10px;margin:3px;font-size:14px;letter-spacing:2px;">' +
				c + '</code>';
		}).join(' ');

		var html =
			'<h3 style="margin-top:0;color:#2e7d32;">' + i18n.recoveryTitle + '</h3>' +
			'<p>' + i18n.recoveryIntro + '</p>' +
			'<div style="background:#fff;border:1px solid #e2e8f0;border-radius:6px;padding:14px;margin:12px 0;line-height:2.2;">' +
				codesHtml +
			'</div>' +
			'<button type="button" id="sentinel-2fa-copy-codes" class="button button-secondary" style="margin-right:8px;">📋 Copy codes</button>' +
			'<button type="button" id="sentinel-2fa-done-btn" class="button button-primary">' + i18n.done + '</button>' +
			'<div id="sentinel-2fa-copy-notice"></div>';

		$wizard.html(cardHtml(html));

		$('#sentinel-2fa-copy-codes').on('click', function () {
			var text = codes.join('\n');
			if (navigator.clipboard) {
				navigator.clipboard.writeText(text).then(function () {
					$('#sentinel-2fa-copy-notice').html('').append(notice('Codes copied to clipboard.', 'success'));
				});
			}
		});

		$('#sentinel-2fa-done-btn').on('click', function () {
			// Page reload to show the updated "Enabled" status.
			$wizard.html('<p style="color:#888;">' + i18n.reload + '</p>');
			window.location.reload();
		});
	}

	// ── Disable 2FA ───────────────────────────────────────────────────────────

	$('#sentinel-2fa-disable-btn').on('click', function () {
		if (!window.confirm(i18n.disableConfirm)) {
			return;
		}

		var userId = $(this).data('user');
		var $btn   = $(this).prop('disabled', true).text('Disabling…');

		$.post(ajaxUrl, {
			action:  'sentinel_2fa_disable',
			nonce:   nonce,
			user_id: userId
		}, function (r) {
			if (r.success) {
				$('#sentinel-2fa-section').after(
					notice(i18n.disabled, 'success')
				);
				window.location.reload();
			} else {
				$btn.prop('disabled', false).text('Disable 2FA');
				$('#sentinel-2fa-section').after(notice(r.data.message));
			}
		}).fail(function () {
			$btn.prop('disabled', false).text('Disable 2FA');
		});
	});

}(jQuery));
