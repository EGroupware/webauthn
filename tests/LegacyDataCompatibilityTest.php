<?php
/**
 * EGroupware WebAuthn - regression test for reading pre-upgrade (webauthn-lib v3) stored tokens
 *
 * @link https://www.egroupware.org
 * @package webauthn
 * @license http://opensource.org/licenses/gpl-license.php GPL - GNU General Public License
 */

namespace EGroupware\WebAuthn;

require_once __DIR__.'/../../api/tests/LoggedInTest.php';
require_once __DIR__.'/../vendor/autoload.php';

use EGroupware\Api\LoggedInTest;

/**
 * Existing installations have real users' tokens stored in egw_webauthn_pubkeys.pubkey_json in
 * the shape webauthn-lib v3's PublicKeyCredentialSource::jsonSerialize() wrote - a JSON object
 * that no longer round-trips through webauthn-lib 5.x's own (de)normalizers by construction
 * (those classes lost jsonSerialize()/createFromArray() entirely, see
 * PublicKeyCredentialSourceRepository::serializer()).
 *
 * This inserts a row using that literal old-format JSON (built by hand here, not generated via
 * any current code path) and proves the current repository can still read it - directly
 * verifying the "no DB migration needed" conclusion from a real code path, rather than resting
 * on manual comparison of the old/new denormalizer expectations.
 *
 * Pass criteria: findOneByCredentialId() and findAllForUserEntity() both return a CredentialRecord
 * whose fields match what was written, decoded from the raw base64url/UUID values in the old JSON.
 */
class LegacyDataCompatibilityTest extends LoggedInTest
{
	protected ?string $credential_id = null;

	protected function tearDown() : void
	{
		if ($this->credential_id !== null)
		{
			$db = $GLOBALS['egw']->db;
			$db->delete(PublicKeyCredentialSourceRepository::TABLE,
				['pubkey_credential_id' => base64_encode($this->credential_id)],
				__LINE__, __FILE__, PublicKeyCredentialSourceRepository::APP);
			$this->credential_id = null;
		}
	}

	/**
	 * base64url-encode without padding, exactly like spomky-labs/base64url's Base64Url::encode()
	 * did in webauthn-lib v3 (the encoding used in the stored JSON's binary fields).
	 */
	protected function base64url(string $data) : string
	{
		return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
	}

	public function testReadsPreV5RegisteredToken()
	{
		$account_id = $GLOBALS['egw_info']['user']['account_id'];
		$install_id = $GLOBALS['egw_info']['server']['install_id'];

		$credential_id = random_bytes(16);
		$this->credential_id = $credential_id;
		$public_key = random_bytes(32);
		$user_handle = $account_id.'-'.$install_id;

		// literal shape of Webauthn\PublicKeyCredentialSource::jsonSerialize() as written by
		// webauthn-lib v3.3.12 (see git history of this file before the 5.3.5 upgrade)
		$legacy_json = json_encode([
			'publicKeyCredentialId' => $this->base64url($credential_id),
			'type' => 'public-key',
			'transports' => [],
			'attestationType' => 'none',
			'trustPath' => ['type' => 'Webauthn\\TrustPath\\EmptyTrustPath'],
			'aaguid' => '00000000-0000-0000-0000-000000000000',
			'credentialPublicKey' => $this->base64url($public_key),
			'userHandle' => $this->base64url($user_handle),
			'counter' => 3,
			'otherUI' => null,
		]);

		$db = $GLOBALS['egw']->db;
		$db->insert(PublicKeyCredentialSourceRepository::TABLE, [
			'pubkey_credential_id' => base64_encode($credential_id),
			'pubkey_json' => $legacy_json,
			'pubkey_created' => time(),
			'account_id' => $account_id,
			'pubkey_deleted' => null,
		], false, __LINE__, __FILE__, PublicKeyCredentialSourceRepository::APP);

		$repo = new PublicKeyCredentialSourceRepository();

		$found = $repo->findOneByCredentialId($credential_id);
		$this->assertNotNull($found, 'A legacy-format row must still be readable by findOneByCredentialId()');
		$this->assertSame($credential_id, $found->publicKeyCredentialId);
		$this->assertSame($user_handle, $found->userHandle);
		$this->assertSame($public_key, $found->credentialPublicKey);
		$this->assertSame(3, $found->counter);
		$this->assertSame('00000000-0000-0000-0000-000000000000', (string)$found->aaguid);

		$all = $repo->findAllForUserEntity(PublicKeyCredentialUserEntity::current());
		$ids = array_map(static fn($c) => $c->publicKeyCredentialId, $all);
		$this->assertContains($credential_id, $ids,
			'findAllForUserEntity() should include the legacy-format row too');
	}
}
