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

$GLOBALS['egw_info'] = array('flags' => array(
	'disable_Template_class'  => True,
	'login'                   => True,
	'currentapp'              => 'login',
));

require('../header.inc.php');

// explicitly include autoloader for our own vendor directory
include __DIR__.'/vendor/autoload.php';

use EGroupware\WebAuthn\Login;

echo Login::ajax_login($_POST);