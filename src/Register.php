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

// explicitly include autoloader for our own vendor directory
include __DIR__.'/../vendor/autoload.php';

use EGroupware\Api;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\Server;
use Zend\Diactoros\ServerRequestFactory;

/**
 * Display tokens of current user under Preferences >> Password & Security
 */
class Register
{
	const APP = 'webauthn';

	/**
	 * Answers preferences_password_security hook
	 *
	 * @param array $data
	 */
	public static function security(array $data)
	{
		unset($data);	// not used, but required by function signature

		Api\Translation::add_app(self::APP);

		$registrationOptions = self::registrationOptions();
		Api\Framework::includeJS('/webauthn/js/app.js');

		return [
			'label' =>	'Register WebAuthn / U2F tokens',
			'name' => 'webauthn.tokens',
			'prepend' => false,
			'data' => [
				'registrationOptions' => $registrationOptions,
				'webauthn' => [
					'get_rows' => __CLASS__.'::getTokens',
					'no_cat' => true,
					'no_filter' => true,
					'no_filter2' => true,
					'filter_no_lang' => true,
					'order' => 'token_updated',
					'sort' => 'DESC',
					'row_id' => 'token_id',
					'default_cols' => '!client_id',
					'actions' => self::tokenActions(),
				],
			],
			'preserve' => [
				'registrationOptions' => $registrationOptions,
			],
			'sel_options' => [
			],
			'save_callback' => __CLASS__.'::action',
		];
	}

	/**
	 * Get options for creation request
	 *
	 * @return string JSON encoded options
	 */
	protected static function registrationOptions()
	{
		// Credential Repository
		$publicKeyCredentialSourceRepository = new PublicKeyCredentialSourceRepository();

		// RP Entity
		$rpEntity = PublicKeyCredentialRpEntity::own();

		// New Server class introduced in v2.1
		$server = new Server(
			$rpEntity,
			$publicKeyCredentialSourceRepository,
			null
		);

		// User Entity
		$userEntity = PublicKeyCredentialUserEntity::current();

		$registeredPublicKeyCredentialSources = $publicKeyCredentialSourceRepository->findAllForUserEntity($userEntity);
		$registeredPublicKeyCredentialDescriptors = array_map(static function(PublicKeyCredentialSource $item) {
			return $item->getPublicKeyCredentialDescriptor();
		}, $registeredPublicKeyCredentialSources);
		$publicKeyCredentialCreationOptions = $server->generatePublicKeyCredentialCreationOptions(
			$userEntity,
			PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
			$registeredPublicKeyCredentialDescriptors
		);

		return json_encode($publicKeyCredentialCreationOptions, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
	}

	/**
	 * Process token registration response from browser
	 *
	 * @param string $response
	 * @param string $options
	 */
	protected static function registration($response, $options)
	{
		$publicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions::createFromString($options);
		//error_log("publicKeyCredentialCreationOptions from session=".json_encode($publicKeyCredentialCreationOptions));

		// Retrieve de data sent by the device
		$data = base64_decode($response);
		//error_log("data from request=$data");

		// Credential Repository
		$publicKeyCredentialSourceRepository = new PublicKeyCredentialSourceRepository();

		// RP Entity
		$rpEntity = PublicKeyCredentialRpEntity::own();

		// New Server class introduced in v2.1
		$server = new Server(
			$rpEntity,
			$publicKeyCredentialSourceRepository,
			null
		);

		try {
			// We init the PSR7 Request object
			$psr7Request = ServerRequestFactory::fromGlobals();

			// Check the response against the request
			$publicKeyCredentialSource = $server->loadAndCheckAttestationResponse($data, $publicKeyCredentialCreationOptions, $psr7Request);

			// Everything is OK here.

			// You can get the Public Key Credential Source. This object should be persisted using the Public Key Credential Source repository
			$publicKeyCredentialSourceRepository->saveCredentialSource($publicKeyCredentialSource);


			//You can also get the PublicKeyCredentialDescriptor.
			$publicKeyCredentialDescriptor = $publicKeyCredentialSource->getPublicKeyCredentialDescriptor();
			//error_log('$publicKeyCredential->getPublicKeyCredentialDescriptor()='.json_encode($publicKeyCredentialDescriptor));
		}
		catch (\Throwable $e) {
			_egw_log_exception($e);
			Api\Framework::message($e->getMessage(), 'error');
		}
		Api\Framework::message(lang('Register WebAuthn / U2F token registered'));
	}

	/**
	 * Callback to run for actions (general on all form posts)
	 *
	 * User password is already checked!
	 *
	 * @param array $content
	 * @return string with success message
	 * @throws Exception on error
	 */
	public static function action(array $content)
	{
		// user registered a new token
		if (is_array($content) && !empty($content['registrationResponse']))
		{
			self::registration($content['registrationResponse'], $content['registrationOptions']);
		}

		if (is_array($content) && $content['tabs'] === 'openid.access_tokens' && $content['nm']['selected'])
		{
			throw new \Exception('Not yet implemented :(');

			/*switch($content['nm']['action'])
			{
				case 'delete':
					$token_repo = new AccessTokenRepository();
					$token_repo->revokeAccessToken(['access_token_id' => $content['nm']['selected']]);
					$refresh_token_repo = new RefreshTokenRepository();
					$refresh_token_repo->revokeRefreshToken(['access_token_id' => $content['nm']['selected']]);
					return (count($content['nm']['selected']) > 1 ?
						count($content['nm']['selected']).' ' : '').
						lang('Access Token revoked.');
			}*/
		}
		unset($content['nm']['selected'], $content['nm']['action'], $content['createResponse']);
	}

	/**
	 * Query tokens for nextmatch widget
	 *
	 * @param array $query with keys 'start', 'search', 'order', 'sort', 'col_filter'
	 *	For other keys like 'filter', 'cat_id' you have to reimplement this method in a derived class.
	 * @param array &$rows returned rows/competitions
	 * @param array &$readonlys eg. to disable buttons based on acl, not use here, maybe in a derived class
	 * @return int number of rows found
	 */
	public static function getTokens(array $query, array &$rows, array &$readonlys)
	{
		$token_repo = new PublicKeyCredentialSourceRepository();
		if (($rows = array_values($token_repo->findAllForUserEntity(PublicKeyCredentialUserEntity::current()))))
		{
			foreach($rows as $key => &$row)
			{
				if (!is_int($key)) continue;

				$row = [
					'pubkey_credential_id' => base64_encode($row->getPublicKeyCredentialId()),
					'pubkey_type' => $row->getType(),
					'pubkey_user_handle' => $row->getUserHandle(),
					'pubkey_counter' => $row->getCounter(),
				];
			}
		}
		return count($rows);
	}

	/**
	 * Get actions for tokens
	 */
	protected static function tokenActions()
	{
		return [
			'delete' => array(
				'caption' => 'Delete',
				'allowOnMultiple' => true,
				'confirm' => 'Delete this token',
			),
		];
	}
}
