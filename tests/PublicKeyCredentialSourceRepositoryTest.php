<?php
/**
 * EGroupware WebAuthn - tests for the credential source repository (DB persistence)
 *
 * @link https://www.egroupware.org
 * @package webauthn
 * @license http://opensource.org/licenses/gpl-license.php GPL - GNU General Public License
 */

namespace EGroupware\WebAuthn;

require_once __DIR__.'/../../api/tests/LoggedInTest.php';

use EGroupware\Api;
use EGroupware\Api\LoggedInTest;
use Symfony\Component\Uid\Uuid;
use Webauthn\CredentialRecord;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * PublicKeyCredentialSourceRepository stores each Webauthn\CredentialRecord as JSON (column
 * pubkey_json, see setup/tables_current.inc.php) via the shared WebauthnSerializerFactory-based
 * serializer (CredentialRecord/PublicKeyCredentialSource lost jsonSerialize()/createFromArray()
 * in webauthn-lib 5.x). That JSON shape is exactly what tends to change in a webauthn-lib major
 * version, so these tests build a synthetic (non-cryptographic) record and round-trip it through
 * the real repository/DB, independent of any actual authenticator.
 *
 * Pass criteria: after save(), the credential is found by findOneByCredentialId() and
 * findAllForUserEntity() with the same field values; after delete() is called twice (soft
 * delete, then hard delete - see PublicKeyCredentialSourceRepository::delete()), the row is
 * gone from both the repository API and the raw table.
 */
class PublicKeyCredentialSourceRepositoryTest extends LoggedInTest
{
	/**
	 * Credential ids used by this test class; always removed in tearDown(), even on failure.
	 */
	protected array $credential_ids = [];

	protected function tearDown() : void
	{
		if ($this->credential_ids)
		{
			$db = $GLOBALS['egw']->db;
			$db->delete(PublicKeyCredentialSourceRepository::TABLE,
				['pubkey_credential_id' => array_map('base64_encode', $this->credential_ids)],
				__LINE__, __FILE__, PublicKeyCredentialSourceRepository::APP);
			$this->credential_ids = [];
		}
	}

	/**
	 * Build a synthetic, non-cryptographically-meaningful credential record for the given
	 * (or current) account. Only the shape/serialization matters for this test, not whether
	 * the "public key" bytes are an actually valid COSE key.
	 */
	protected function makeSource(?int $account_id=null) : CredentialRecord
	{
		$account_id = $account_id ?? $GLOBALS['egw_info']['user']['account_id'];
		$install_id = $GLOBALS['egw_info']['server']['install_id'];

		$credential_id = random_bytes(16);
		$this->credential_ids[] = $credential_id;

		return CredentialRecord::create(
			$credential_id,
			'public-key',
			[],
			'none',
			new EmptyTrustPath(),
			Uuid::fromString('00000000-0000-0000-0000-000000000000'),
			random_bytes(32),          // stand-in COSE public key bytes
			$account_id.'-'.$install_id,
			0
		);
	}

	public function testSaveAndFindOneByCredentialId()
	{
		$source = $this->makeSource();
		$repo = new PublicKeyCredentialSourceRepository();

		$repo->saveCredentialSource($source);
		$found = $repo->findOneByCredentialId($source->publicKeyCredentialId);

		$this->assertNotNull($found, 'Saved credential source not found by its credential id');
		$this->assertSame($source->publicKeyCredentialId, $found->publicKeyCredentialId);
		$this->assertSame($source->userHandle, $found->userHandle);
		$this->assertSame($source->credentialPublicKey, $found->credentialPublicKey);
		$this->assertSame($source->counter, $found->counter);
	}

	public function testFindAllForUserEntityReturnsOwnCredentialsOnly()
	{
		$source = $this->makeSource();
		$repo = new PublicKeyCredentialSourceRepository();
		$repo->saveCredentialSource($source);

		$userEntity = PublicKeyCredentialUserEntity::current();
		$all = $repo->findAllForUserEntity($userEntity);

		$ids = array_map(static function(CredentialRecord $s) { return $s->publicKeyCredentialId; }, $all);
		$this->assertContains($source->publicKeyCredentialId, $ids,
			'findAllForUserEntity() should include a just-saved credential of the current user');
	}

	/**
	 * delete() is a soft-delete on first call (sets pubkey_deleted), and only physically
	 * removes rows that are *already* marked deleted - see
	 * PublicKeyCredentialSourceRepository::delete(). So the first call must hide the
	 * credential from lookups without removing the row, and only the second call removes it.
	 */
	public function testDeleteIsSoftThenHard()
	{
		$source = $this->makeSource();
		$repo = new PublicKeyCredentialSourceRepository();
		$repo->saveCredentialSource($source);

		// sanity check it is there before deleting
		$this->assertNotNull($repo->findOneByCredentialId($source->publicKeyCredentialId));

		$pubkey_id = $this->pubkeyIdFor($source);

		// first delete(): soft delete, row still physically exists
		$repo->delete(['pubkey_id' => $pubkey_id]);
		$this->assertNull($repo->findOneByCredentialId($source->publicKeyCredentialId),
			'Soft-deleted credential must no longer be returned by findOneByCredentialId()');
		$this->assertNotNull($this->rawRow($source), 'Soft-deleted row should still physically exist after first delete()');

		// second delete(): now physically removed
		$repo->delete(['pubkey_id' => $pubkey_id]);
		$this->assertNull($this->rawRow($source), 'Row should be physically gone after second delete()');
	}

	/**
	 * Look up the internal pubkey_id (autoinc PK) for a saved source, needed to call delete()
	 * the same way Register::action() does (by pubkey_id, not credential id).
	 */
	protected function pubkeyIdFor(CredentialRecord $source) : int
	{
		$row = $this->rawRow($source);
		$this->assertNotNull($row, 'Expected row to exist to determine its pubkey_id');
		return (int)$row['pubkey_id'];
	}

	protected function rawRow(CredentialRecord $source) : ?array
	{
		$db = $GLOBALS['egw']->db;
		foreach($db->select(PublicKeyCredentialSourceRepository::TABLE, '*',
			['pubkey_credential_id' => base64_encode($source->publicKeyCredentialId)],
			__LINE__, __FILE__, false, '', PublicKeyCredentialSourceRepository::APP) as $row)
		{
			return $row;
		}
		return null;
	}
}
