<?php
/**
 * EGroupware WebAuthn - tests for registration/login option generation (webauthn-lib API surface)
 *
 * @link https://www.egroupware.org
 * @package webauthn
 * @license http://opensource.org/licenses/gpl-license.php GPL - GNU General Public License
 */

namespace EGroupware\WebAuthn;

require_once __DIR__.'/../../api/tests/LoggedInTest.php';
require_once __DIR__.'/../vendor/autoload.php';

use EGroupware\Api\LoggedInTest;
use ReflectionMethod;
use Webauthn\PublicKeyCredentialRequestOptions;

/**
 * Register::registrationOptions() and the option-generation half of Login::ajax_login() build
 * PublicKeyCredentialCreationOptions/PublicKeyCredentialRequestOptions - the JSON handed to
 * navigator.credentials.create()/.get() in the browser - directly (webauthn-lib 5.x removed the
 * Server facade that used to generate these). A webauthn-lib upgrade that renames/reorders the
 * ::create() factories, the Cose\Algorithm\Manager pubKeyCredParams building, or the shared
 * serializer's output shape would otherwise only surface as a broken "Register token" button.
 *
 * Pass criteria: both calls return decodable JSON containing the fields the frontend
 * (js/app.ts, js/login.js) actually reads.
 */
class OptionsGenerationTest extends LoggedInTest
{
	protected $orig_http_host;

	/**
	 * Set HTTP_HOST to reflect a real HTTP request (PHPUnit's CLI bootstrap doesn't set one),
	 * like PublicKeyCredentialRpEntityTest does, so PublicKeyCredentialRpEntity::own() behaves
	 * as it would in production.
	 */
	protected function setUp() : void
	{
		$this->orig_http_host = $_SERVER['HTTP_HOST'] ?? null;
		$_SERVER['HTTP_HOST'] = 'phpunit.example.org';
	}

	protected function tearDown() : void
	{
		$_SERVER['HTTP_HOST'] = $this->orig_http_host;
	}

	/**
	 * Exercises the exact production code path used by Preferences > Password & Security to
	 * offer a new token registration.
	 */
	public function testRegistrationOptionsShape()
	{
		$method = new ReflectionMethod(Register::class, 'registrationOptions');
		$method->setAccessible(true);

		$json = $method->invoke(null);
		$data = json_decode($json, true);

		$this->assertIsArray($data, 'registrationOptions() must return valid JSON');
		$this->assertArrayHasKey('rp', $data);
		$this->assertArrayHasKey('name', $data['rp'],
			'rp.name must survive serialization - the browser rejects navigator.credentials.create() '.
			'if this required PublicKeyCredentialEntity.name member is missing (regression: it was '.
			'briefly dropped when RpEntity::own() passed \'\' following a webauthn-lib deprecation '.
			'notice that turned out not to apply to the browser-facing wire format)');
		$this->assertNotSame('', $data['rp']['name']);
		$this->assertArrayHasKey('user', $data);
		$this->assertArrayHasKey('challenge', $data);
		$this->assertNotEmpty($data['challenge'], 'challenge must not be empty - it is the anti-replay nonce');
		$this->assertArrayHasKey('pubKeyCredParams', $data);
		$this->assertNotEmpty($data['pubKeyCredParams'], 'at least one signature algorithm must be offered');
		$this->assertSame('none', $data['attestation'] ?? null,
			'Register::security() explicitly requests ATTESTATION_CONVEYANCE_PREFERENCE_NONE');
	}

	/**
	 * Login::ajax_login() builds request options inline (not a standalone method); this
	 * reproduces that same PublicKeyCredentialRequestOptions::create() call for a synthetic user
	 * with one known credential descriptor, so that (distinct) construction path is covered too.
	 */
	public function testRequestOptionsShape()
	{
		$repo = new PublicKeyCredentialSourceRepository();
		$rpEntity = PublicKeyCredentialRpEntity::own();

		$userEntity = PublicKeyCredentialUserEntity::current();
		$descriptors = array_map(
			static function($source) { return $source->getPublicKeyCredentialDescriptor(); },
			$repo->findAllForUserEntity($userEntity)
		);

		$options = PublicKeyCredentialRequestOptions::create(
			random_bytes(32),
			$rpEntity->id,
			$descriptors,
			PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED
		);
		$json = PublicKeyCredentialSourceRepository::serializer()->serialize($options, 'json');
		$data = json_decode($json, true);

		$this->assertIsArray($data, 'serializing PublicKeyCredentialRequestOptions must produce valid JSON');
		$this->assertArrayHasKey('challenge', $data);
		$this->assertNotEmpty($data['challenge'], 'challenge must not be empty - it is the anti-replay nonce');
		$this->assertSame('preferred', $data['userVerification'] ?? null);
	}
}
