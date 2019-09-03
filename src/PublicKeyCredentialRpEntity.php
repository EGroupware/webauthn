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
			empty($GLOBALS['egw_info']['server']['site_title']) ? 'EGroupware' : $GLOBALS['egw_info']['server']['site_title'], //Name
			preg_replace('/:.*$/', '', $_SERVER['HTTP_HOST']),              //ID
			null                            //Icon
		);
	}
}