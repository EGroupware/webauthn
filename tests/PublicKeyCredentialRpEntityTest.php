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
 * PublicKeyCredentialRpEntity::own() maps the configured site title and the current request's
 * host onto the webauthn-lib RP entity constructor. Covered here so a webauthn-lib upgrade that
 * renames/reorders those constructor arguments, or changes what gets serialized to the browser,
 * gets caught here instead of only showing up as a confusing WebAuthn browser-side failure.
 *
 * webauthn-lib 5.3 deprecated the RP entity's "name" field (removed entirely in 6.0) and replaced
 * getName()/getId() getters with plain public properties - own() was briefly changed to pass ''
 * for name to follow that deprecation, which broke real token registration: the browser's
 * WebAuthn API still requires PublicKeyCredentialEntity.name to be a non-empty string, and
 * webauthn-lib's own normalizer drops empty values from the wire JSON entirely, so
 * navigator.credentials.create() then rejected the missing required member ("Failed to read the
 * 'name' property ... Required member is undefined"). own() must keep passing a real name for as
 * long as we're on 5.x; this is asserted both on the object and on the actual serialized JSON, to
 * guard against that exact silent-wire-format regression happening again.
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

		$this->assertSame('PHPUnit Test Site', $rp->name, 'RP name should come from server site_title');
		$this->assertSame('phpunit.example.org', $rp->id, 'RP id should be HTTP_HOST with any :port stripped');
	}

	/**
	 * Falls back to the literal string 'EGroupware' when no site title is configured.
	 */
	public function testOwnFallsBackToEGroupwareName()
	{
		unset($GLOBALS['egw_info']['server']['site_title']);
		$_SERVER['HTTP_HOST'] = 'phpunit.example.org';

		$rp = PublicKeyCredentialRpEntity::own();

		$this->assertSame('EGroupware', $rp->name);
	}

	/**
	 * Regression guard: webauthn-lib's PublicKeyCredentialRpEntityDenormalizer normalizer drops
	 * empty-string values entirely, so the "name" key must actually survive serialization as a
	 * non-empty string - the browser enforces this itself and refuses navigator.credentials.
	 * create() otherwise, which the object-level assertions above cannot catch on their own.
	 */
	public function testOwnSerializesNonEmptyName()
	{
		$GLOBALS['egw_info']['server']['site_title'] = 'PHPUnit Test Site';
		$_SERVER['HTTP_HOST'] = 'phpunit.example.org';

		$rp = PublicKeyCredentialRpEntity::own();
		$json = PublicKeyCredentialSourceRepository::serializer()->serialize($rp, 'json');
		$data = json_decode($json, true);

		$this->assertArrayHasKey('name', $data, 'rp.name must survive serialization, not be dropped as empty');
		$this->assertNotSame('', $data['name']);
	}
}
