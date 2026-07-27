<?php
/**
 * EGroupware WebAuthn - tests for the Relying Party entity factory
 *
 * @link https://www.egroupware.org
 * @package webauthn
 * @license https://www.egroupware.org/EPL EPL - EGroupware EPL License
 */

namespace EGroupware\WebAuthn;

require_once __DIR__.'/../../api/tests/LoggedInTest.php';
require_once __DIR__.'/../vendor/autoload.php';

use EGroupware\Api\LoggedInTest;

/**
 * PublicKeyCredentialRpEntity::own() just maps a couple of EGroupware globals onto the
 * webauthn-lib RP entity constructor. Covered here so a webauthn-lib upgrade that renames
 * or reorders those constructor arguments gets caught immediately, instead of only showing
 * up as a confusing WebAuthn browser-side failure.
 */
class PublicKeyCredentialRpEntityTest extends LoggedInTest
{
	protected $orig_site_title;
	protected $orig_http_host;

	protected function setUp() : void
	{
		$this->orig_site_title = $GLOBALS['egw_info']['server']['site_title'] ?? null;
		$this->orig_http_host = $_SERVER['HTTP_HOST'] ?? null;
	}

	protected function tearDown() : void
	{
		$GLOBALS['egw_info']['server']['site_title'] = $this->orig_site_title;
		$_SERVER['HTTP_HOST'] = $this->orig_http_host;
	}

	/**
	 * own() must use the configured site title as RP name, and the (port-stripped) HTTP
	 * host as RP ID - the RP ID is compared by the browser/authenticator against the origin,
	 * so a regression here breaks every registration and login.
	 */
	public function testOwnUsesSiteTitleAndHost()
	{
		$GLOBALS['egw_info']['server']['site_title'] = 'PHPUnit Test Site';
		$_SERVER['HTTP_HOST'] = 'phpunit.example.org:8080';

		$rp = PublicKeyCredentialRpEntity::own();

		$this->assertSame('PHPUnit Test Site', $rp->getName(), 'RP name should come from server site_title');
		$this->assertSame('phpunit.example.org', $rp->getId(), 'RP id should be HTTP_HOST with any :port stripped');
	}

	/**
	 * Falls back to the literal string 'EGroupware' when no site title is configured.
	 */
	public function testOwnFallsBackToEGroupwareName()
	{
		unset($GLOBALS['egw_info']['server']['site_title']);
		$_SERVER['HTTP_HOST'] = 'phpunit.example.org';

		$rp = PublicKeyCredentialRpEntity::own();

		$this->assertSame('EGroupware', $rp->getName());
	}
}
