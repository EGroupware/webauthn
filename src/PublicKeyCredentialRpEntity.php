<?php
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

namespace EGroupware\WebAuthn;

class PublicKeyCredentialRpEntity extends Webauthn\PublicKeyCredentialRpEntity
{
	/**
	 * Get own RP entity
	 */
	public static function own()
	{
		return new self(
			// Name: webauthn-lib 5.3 deprecates this param (removed in 6.0, unused server-side),
			// but the browser's WebAuthn API still requires PublicKeyCredentialEntity.name to be
			// a non-empty string - webauthn-lib's own normalizer drops empty values from the
			// wire JSON entirely, and navigator.credentials.create() then rejects the missing
			// required member. So a real value is still needed here for as long as we're on 5.x.
			empty($GLOBALS['egw_info']['server']['site_title']) ? 'EGroupware' : $GLOBALS['egw_info']['server']['site_title'],
			preg_replace('/:.*$/', '', $_SERVER['HTTP_HOST']),              //ID
			null                            //Icon
		);
	}
}