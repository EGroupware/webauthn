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

/**
 * JavaScript for WebAuthn
 *
 * @augments AppJS
 */
app.classes.webauthn = AppJS.extend(
{
	appname: 'webauthn',
	/**
	 * et2 widget container
	 */
	et2: null,
	/**
	 * path widget
	 */

	/**
	 * Constructor
	 *
	 * @memberOf app.timesheet
	 */
	init: function()
	{
		// call parent
		this._super.apply(this, arguments);
	},

	/**
	 * Destructor
	 */
	destroy: function()
	{
		delete this.et2;
		// call parent
		this._super.apply(this, arguments);
	},

	/**
	 * This function is called when the etemplate2 object is loaded
	 * and ready.  If you must store a reference to the et2 object,
	 * make sure to clean it up in destroy().
	 *
	 * @param et2 etemplate2 Newly ready object
	 */
	et2_ready: function(et2)
	{
		// call parent
		this._super.apply(this, arguments);

	},

	/**
	 * Convert array to base64 encoded string
	 *
	 * @param {Array} a
	 * @returns {string}
	 */
	arrayToBase64String: function(a)
	{
		return btoa(String.fromCharCode(...a));
	},

	/**
	 * Convert base64url encoded string into a base64 encoded one
	 *
	 * @param {string} input
	 * @returns {string}
	 */
	base64url2base64: function (input)
	{
		// Replace non-url compatible chars with base64 standard chars
		input = input
			.replace(/-/g, '+')
			.replace(/_/g, '/');

		// Pad out with standard base64 required padding characters
		const pad = input.length % 4;
		if (pad)
		{
			if(pad === 1)
			{
				throw new Error('InvalidLengthError: Input base64url string is the wrong length to determine padding');
			}
			input += new Array(5-pad).join('=');
		}

		return input;
	},

	/**
	 * User pressed button to register new token
	 *
	 * @param {et2_widget} _widget
	 */
	register: function(_widget)
	{
		if (!this.et2) this.et2 = app.preferences.et2;

		// check if password is filled out, as we will not store pubkey without
		const password = this.et2.getWidgetById('password');
		if (!password.submit())
		{
			return false;
		}

		const self = this;
		const widget = _widget;
		const publicKey = JSON.parse(
			this.et2.getArrayMgr('content').getEntry('registrationOptions'));

		publicKey.challenge = Uint8Array.from(window.atob(this.base64url2base64(publicKey.challenge)), function(c){ return c.charCodeAt(0); });
		publicKey.user.id = Uint8Array.from(window.atob(publicKey.user.id), function(c){ return c.charCodeAt(0); });
		if (publicKey.excludeCredentials)
		{
			publicKey.excludeCredentials = publicKey.excludeCredentials.map(function(data) {
				data.id = Uint8Array.from(window.atob(self.base64url2base64(data.id)), function(c){return c.charCodeAt(0);});
				return data;
			});
		}

		navigator.credentials.create({ 'publicKey': publicKey })
			.then(function(data) {
				const publicKeyCredential = {
					id: data.id,
					type: data.type,
					rawId: self.arrayToBase64String(new Uint8Array(data.rawId)),
					response: {
						clientDataJSON: self.arrayToBase64String(new Uint8Array(data.response.clientDataJSON)),
						attestationObject: self.arrayToBase64String(new Uint8Array(data.response.attestationObject))
					}
				};
				const registrationResponse = self.et2.getWidgetById('registrationResponse');
				registrationResponse.set_value(btoa(JSON.stringify(publicKeyCredential)));
				self.et2._inst.submit(widget);
			})
			.catch(function(error) {
				self.egw.message(error.message, 'error');
				console.log('FAIL', error);
			});
	}
});
