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

use EGroupware\Api;
use Webauthn\PublicKeyCredentialSourceRepository as PublicKeyCredentialSourceRepositoryInterface;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialUserEntity;

class PublicKeyCredentialSourceRepository  extends Api\Storage\Base implements PublicKeyCredentialSourceRepositoryInterface
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
	 * Find public key credentials by their ID
	 *
	 * @param string $publicKeyCredentialId
	 * @return PublicKeyCredentialSource|null
	 */
    public function findOneByCredentialId(string $publicKeyCredentialId): ?PublicKeyCredentialSource
	{
		if (($data = $this->read([
			'pubkey_credential_id' => base64_encode($publicKeyCredentialId),
			'pubkey_deleted IS NULL',
		])))
		{
            return PublicKeyCredentialSource::createFromArray(json_decode($data['pubkey_json'], true));
		}
		return null;
	}

    /**
	 * Find all (undeleted) public key credentials of a user
	 *
	 * @param PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity
     * @return PublicKeyCredentialSource[]
     */
    public function findAllForUserEntity(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array
	{
		$sources = [];
		foreach((array)$this->search('', 'pubkey_json', '', '', '', false, 'AND', false, [
			'account_id' => (int)$publicKeyCredentialUserEntity->getId(),
			'pubkey_deleted IS NULL',
		]) as $row)
		{
			$sources[] = PublicKeyCredentialSource::createFromArray(json_decode($row['pubkey_json'], true));
		}
		//error_log(__METHOD__."(".json_encode($publicKeyCredentialUserEntity).") returning ".json_encode($sources));
		return $sources;
	}

	/**
	 * Save / persist given public key credentials
	 *
	 * @param PublicKeyCredentialSource $publicKeyCredentialSource
	 */
    public function saveCredentialSource(PublicKeyCredentialSource $publicKeyCredentialSource): void
	{
		//error_log(__METHOD__."(".json_encode($publicKeyCredentialSource).")");

		if (!$this->read(['pubkey_credential_id' => base64_encode($publicKeyCredentialSource->getPublicKeyCredentialId())]))
		{
			$this->init([
				'pubkey_created' => time(),
				'account_id' => (int)$publicKeyCredentialSource->getUserHandle(),
				'pubkey_credential_id' => base64_encode($publicKeyCredentialSource->getPublicKeyCredentialId()),
				'pubkey_deleted' => null,
			]);
		}
		$this->save([
			'pubkey_json' => json_encode($publicKeyCredentialSource, JSON_UNESCAPED_SLASHES),
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
