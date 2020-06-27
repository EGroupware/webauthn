/**
 * EGroupware WebAuthn
 *
 * @link https://www.egroupware.org
 * @author Ralf Becker <rb-At-egroupware.org>
 * @package webauthn
 * @license https://www.egroupware.org/EPL EPL - EGroupware EPL License
 *
 * Based on the following MIT Licensed packages:
 * @link https://github.com/web-auth/webauthn-framework
 */

egw_LAB.wait(function()
{
	jQuery(document).ready(function()
	{
		jQuery('input[type="submit"][name="submitit"]').click(function(event)
		{
			event.preventDefault();

			jQuery.ajax({
				url: egw.webserverUrl+'/webauthn/ajax_check_login.php',
				method: 'POST',
				//async: false,
				data: jQuery('form').serialize(),
				dataType: 'json',
			}).then(function(_data)
			{
				const publicKey = _data;

				publicKey.challenge = Uint8Array.from(window.atob(base64url2base64(publicKey.challenge)), function(c){return c.charCodeAt(0);});
				if (publicKey.allowCredentials) {
					publicKey.allowCredentials = publicKey.allowCredentials.map(function(data) {
						data.id = Uint8Array.from(window.atob(base64url2base64(data.id)), function(c){return c.charCodeAt(0);});
						return data;
					});
				}

				navigator.credentials.get({ 'publicKey': publicKey })
					.then(function(data){
						const publicKeyCredential = {
							id: data.id,
							type: data.type,
							rawId: arrayToBase64String(new Uint8Array(data.rawId)),
							response: {
								authenticatorData: arrayToBase64String(new Uint8Array(data.response.authenticatorData)),
								clientDataJSON: arrayToBase64String(new Uint8Array(data.response.clientDataJSON)),
								signature: arrayToBase64String(new Uint8Array(data.response.signature)),
								userHandle: data.response.userHandle ? arrayToBase64String(new Uint8Array(data.response.userHandle)) : null
							}
						};
						const response = jQuery('<input type="hidden" name="credentialsResponse"/>').val(btoa(JSON.stringify(publicKeyCredential)));
						jQuery('form')
							.append(response)
							.submit();
					})
					.catch(function(error){
						console.log('FAIL', error);
						jQuery('form').submit();
					});

			}, function(_data)	// no token registered for give user
			{
				jQuery('form').submit();
				return;
			});
		});

		function arrayToBase64String(a) {
			return btoa(String.fromCharCode(...a));
		}

		function base64url2base64(input) {
			// Replace non-url compatible chars with base64 standard chars
			input = input
				.replace(/-/g, '+')
				.replace(/_/g, '/');

			// Pad out with standard base64 required padding characters
			const pad = input.length % 4;
			if(pad) {
				if(pad === 1) {
					throw new Error('InvalidLengthError: Input base64url string is the wrong length to determine padding');
				}
				input += new Array(5-pad).join('=');
			}

			return input;
		}
	});
});
