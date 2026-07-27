<?php
/**
 * EGroupware WebAuthn - tests for registration/login option generation (Server API surface)
 *
 * @link https://www.egroupware.org
 * @package webauthn
 * @license https://www.egroupware.org/EPL EPL - EGroupware EPL License
 */

namespace EGroupware\WebAuthn;

require_once __DIR__.'/../../api/tests/LoggedInTest.php';
require_once __DIR__.'/../vendor/autoload.php';

use EGroupware\Api\LoggedInTest;
use ReflectionMethod;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\Server;

/**
 * Register::registrationOptions() and the option-generation half of Login::ajax_login() are
 * the two places that call into Webauthn\Server to build the JSON handed to navigator.
 * credentials.create()/.get() in the browser. These calls are the main webauthn-lib
 * *construction-time* API surface (as opposed to the verification-time
 * loadAndCheckAttestationResponse()/loadAndCheckAssertionResponse() calls, not covered here -
 * see README for planned follow-up). A webauthn-lib upgrade that renames/reorders these
 * methods or their constants would otherwise only surface as a broken "Register token" button.
 *
 * Pass criteria: both calls return decodable JSON containing the fields the frontend
 * (js/app.ts, js/login.js) actually reads.
 */
class OptionsGenerationTest extends LoggedInTest
{
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
	 * reproduces that same Server/RpEntity/UserEntity call sequence for a synthetic user with
	 * one known credential descriptor, so the generatePublicKeyCredentialRequestOptions() API
	 * (distinct from the creation-options one above) is covered too.
	 */
	public function testRequestOptionsShape()
	{
		$repo = new PublicKeyCredentialSourceRepository();
		$rpEntity = PublicKeyCredentialRpEntity::own();
		$server = new Server($rpEntity, $repo, null);

		$userEntity = PublicKeyCredentialUserEntity::current();
		$descriptors = array_map(
			static function($source) { return $source->getPublicKeyCredentialDescriptor(); },
			$repo->findAllForUserEntity($userEntity)
		);

		$options = $server->generatePublicKeyCredentialRequestOptions(
			PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED,
			$descriptors
		);
		$data = json_decode(json_encode($options, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), true);

		$this->assertIsArray($data, 'generatePublicKeyCredentialRequestOptions() must produce valid JSON');
		$this->assertArrayHasKey('challenge', $data);
		$this->assertNotEmpty($data['challenge'], 'challenge must not be empty - it is the anti-replay nonce');
		$this->assertSame('preferred', $data['userVerification'] ?? null);
	}
}
