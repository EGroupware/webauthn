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

use EGroupware\WebAuthn;

$setup_info['webauthn']['name']    = 'webauthn';
$setup_info['webauthn']['title']   = 'WebAuthn';
$setup_info['webauthn']['version'] = '21.1';
$setup_info['webauthn']['app_order'] = 1;
$setup_info['webauthn']['tables']  = array('egw_webauthn_pubkeys');
$setup_info['webauthn']['enable']  = 2;
$setup_info['webauthn']['autoinstall'] = true;	// install automatically on update

$setup_info['webauthn']['author'] =
$setup_info['webauthn']['maintainer'] = [
	'name' => 'Ralf Becker',
	'email' => 'rb@egroupware.org',
	'url'   => 'https://www.egroupware.org',
];
$setup_info['webauthn']['license']  = array(
	'name' => 'EGroupware EPL license',
	'url'  => 'https://www.egroupware.org/EPL',
);
$setup_info['webauthn']['description'] = 'WebAuthn (Fido2) as 2. Factor for EGroupware';

// The hooks this app includes, needed for hooks registration
//$setup_info['webauthn']['hooks']['admin']   = OpenID\Ui::class.'::menu';
//$setup_info['webauthn']['hooks']['sidebox']   = OpenID\Ui::class.'::menu';
$setup_info['webauthn']['hooks']['preferences_security'] = WebAuthn\Register::class.'::security';
$setup_info['webauthn']['hooks']['login_page'] = WebAuthn\Login::class.'::page';
$setup_info['webauthn']['hooks']['multifactor_policy'] = WebAuthn\Login::class.'::multifactor';

$setup_info['webauthn']['depends'][] = [
	'appname' => 'api',
	'versions' => ['21.1'],
];

