<?php
/**
 * EGroupware WebAuthn
 *
 * @link https://www.egroupware.org
 * @author Ralf Becker <rb-At-egroupware.org>
 * @package webauthn
 * @license http://opensource.org/licenses/gpl-license.php GPL - GNU General Public License
 *
 * Based on the following MIT Licensed packages:
 * @link https://github.com/web-auth/webauthn-framework
 */

namespace EGroupware\WebAuthn;

// explicitly include autoloader for our own vendor directory
include __DIR__.'/../vendor/autoload.php';

use EGroupware\Api;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredentialUserEntity;
use Symfony\Component\Serializer\SerializerInterface;

/**
 * Note: webauthn-lib 5.x no longer defines a PublicKeyCredentialSourceRepository interface
 * (the validator classes take an already-looked-up CredentialRecord instead), so this class
 * is a plain repository with the same method names as before, not an interface implementation.
 */
class PublicKeyCredentialSourceRepository extends Api\Storage\Base
{
	const APP = 'webauthn';

	/**
	 * Table name
	 */
	const TABLE = 'egw_webauthn_pubkeys';

	/**
	 * Constructor
	 */
	public function __construct()
	{
		parent::__construct(self::APP, self::TABLE, null, '', true);
	}

	/**
	 * Shared (de)serializer for PublicKeyCredentialSource / options / responses, as recommended
	 * by webauthn-lib 5.x (jsonSerialize()/createFromArray() were removed from those classes)
	 *
	 * @return SerializerInterface
	 */
	public static function serializer() : SerializerInterface
	{
		return (new WebauthnSerializerFactory(new AttestationStatementSupportManager()))->create();
	}

	/**
	 * Find public key credentials by their ID
	 *
	 * Deserializes into CredentialRecord, not the (webauthn-lib 5.3+ deprecated, removed in 6.0)
	 * PublicKeyCredentialSource subclass - old rows stored by the earlier PublicKeyCredentialSource
	 * are field-for-field compatible, CredentialRecord just has no extra properties of its own.
	 *
	 * @param string $publicKeyCredentialId
	 * @return CredentialRecord|null
	 */
    public function findOneByCredentialId(string $publicKeyCredentialId): ?CredentialRecord
	{
		if (($data = $this->read([
			'pubkey_credential_id' => base64_encode($publicKeyCredentialId),
			'pubkey_deleted IS NULL',
		])))
		{
            return self::serializer()->deserialize($data['pubkey_json'], CredentialRecord::class, 'json');
		}
		return null;
	}

    /**
	 * Find all (undeleted) public key credentials of a user
	 *
	 * @param PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity
     * @return CredentialRecord[]
     */
    public function findAllForUserEntity(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array
	{
		$sources = [];
		foreach((array)$this->search('', 'pubkey_json', '', '', '', false, 'AND', false, [
			'account_id' => (int)$publicKeyCredentialUserEntity->id,
			'pubkey_deleted IS NULL',
		]) as $row)
		{
			$sources[] = self::serializer()->deserialize($row['pubkey_json'], CredentialRecord::class, 'json');
		}
		//error_log(__METHOD__."(".json_encode($publicKeyCredentialUserEntity).") returning ".json_encode($sources));
		return $sources;
	}

	/**
	 * Save / persist given public key credentials
	 *
	 * @param CredentialRecord $publicKeyCredentialSource
	 */
    public function saveCredentialSource(CredentialRecord $publicKeyCredentialSource): void
	{
		//error_log(__METHOD__."(".json_encode($publicKeyCredentialSource).")");

		if (!$this->read(['pubkey_credential_id' => base64_encode($publicKeyCredentialSource->publicKeyCredentialId)]))
		{
			$this->init([
				'pubkey_created' => time(),
				'account_id' => (int)$publicKeyCredentialSource->userHandle,
				'pubkey_credential_id' => base64_encode($publicKeyCredentialSource->publicKeyCredentialId),
				'pubkey_deleted' => null,
			]);
		}
		$this->save([
			'pubkey_json' => self::serializer()->serialize($publicKeyCredentialSource, 'json'),
		]);
	}

	/**
	 * Delete public key credentials
	 *
	 * Reimplemented to set pubkey_deleted, if not already set, otherwise delete
	 *
	 * @param array|int $keys =null if given array with col => value pairs to characterise the rows to delete, or integer autoinc id
	 * @param boolean $only_return_query =false NOT supported!
	 * @return int|array affected rows, should be 1 if ok, 0 if an error or array with id's if $only_return_ids
	 */
	public function delete($keys = null, $only_return_query = false)
	{
		unset($only_return_query);	// not used, but required by function signature

		if (!is_array($keys)) $keys = ['pubkey_id' => $keys];

		// finally delete already marked as deleted tokens
		$keys[999] = 'pubkey_deleted IS NOT NULL';
		$this->db->delete(self::TABLE, $keys, __LINE__, __FILE__, self::APP);
		$affected = $this->db->affected_rows();

		// mark rest as of now deleted
		unset($keys[999]);
		$this->db->update(self::TABLE, [
			'pubkey_deleted' => time()
		], $keys, __LINE__, __FILE__, self::APP);
		$affected += $this->db->affected_rows();

		return $affected;
	}
}
