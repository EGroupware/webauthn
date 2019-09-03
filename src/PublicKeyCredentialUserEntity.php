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

//use EGroupware\Api;

class PublicKeyCredentialUserEntity extends Webauthn\PublicKeyCredentialUserEntity
{
	/**
	 * Create a user-entity object for current EGroupware user
	 */
	public static function current()
	{
		return new self(
			'@'.$GLOBALS['egw_info']['user']['account_lid'],	//Name
			$GLOBALS['egw_info']['user']['account_id'].'-'.$GLOBALS['egw_info']['server']['install_id'],	//ID
			$GLOBALS['egw_info']['user']['account_fullname'],	//Display name
			null	//Icon
		);
	}
}
