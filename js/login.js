/**
 * EGroupware WebAuthn
 *
 * @link https://www.egroupware.org
 * @author Ralf Becker <rb-At-egroupware.org>
 * @package webauthn
 * @license http://opensource.org/licenses/gpl-license.php GPL - GNU General Public License
 *
 * Based on the following MIT Licensed packages:
 * @link https://github.com/web-auth/webauthn-framework
 */

const ready = (callback) => {
	if (document.readyState != "loading") callback();
	else document.addEventListener("DOMContentLoaded", callback);
}

ready(() => {
	const loginForm = document.querySelector('form[name="login_form"]') || document.querySelector('form');
	const submitForm = loginForm.submit.bind(loginForm);

	// for JS calling loginForm.submit() we have to replace the method
	loginForm.submit = (() =>
	{
		fetch(egw.webserverUrl+'/webauthn/ajax_check_login.php', {
			method: 'POST',
			headers: {'Content-Type': 'application/x-www-form-urlencoded'},
			body: new URLSearchParams(new FormData(loginForm)).toString(),
		}).then((response) => response.ok ? response.json() : Promise.reject(response))
		.then((publicKey) =>
		{
			publicKey.challenge = Uint8Array.from(window.atob(base64url2base64(publicKey.challenge)), (c) => c.charCodeAt(0));
			if (publicKey.allowCredentials) {
				publicKey.allowCredentials = publicKey.allowCredentials.map((data) => {
					data.id = Uint8Array.from(window.atob(base64url2base64(data.id)), (c) => c.charCodeAt(0));
					return data;
				});
			}

			navigator.credentials.get({ 'publicKey': publicKey })
				.then((data) => {
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
					const credentialsResponse = document.createElement('input');
					credentialsResponse.type = 'hidden';
					credentialsResponse.name = 'credentialsResponse';
					credentialsResponse.value = btoa(JSON.stringify(publicKeyCredential));
					loginForm.appendChild(credentialsResponse);
					submitForm();
				})
				.catch((error) => {
					console.log('FAIL', error);
					submitForm();
				});

		})
		.catch(() =>	// no token registered for given user, or request failed
		{
			submitForm();
		});
	});

	// for regular submit buttons, we have to add an event-listener
	loginForm.addEventListener('submit', (event) => {
		event.preventDefault();

		loginForm.submit();
	});

	function arrayToBase64String(a) {
		// webauthn-lib 5.x decodes several response fields (eg. clientDataJSON, id) with a strict
		// base64url decoder that rejects standard base64's '+'/'/' and '=' padding - browser's
		// btoa() alone produces exactly that, so convert to unpadded base64url here.
		return btoa(String.fromCharCode(...a))
			.replace(/\+/g, '-')
			.replace(/\//g, '_')
			.replace(/=+$/, '');
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