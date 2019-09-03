<?php
/**
 * eGroupWare - Setup
 * http://www.egroupware.org
 * Created by eTemplates DB-Tools written by ralfbecker@outdoor-training.de
 *
 * @license http://opensource.org/licenses/gpl-license.php GPL - GNU General Public License
 * @package webauthn
 * @subpackage setup
 * @version $Id$
 */


$phpgw_baseline = array(
	'egw_webauthn_pubkeys' => array(
		'fd' => array(
			'pubkey_id' => array('type' => 'auto','nullable' => False),
			'pubkey_credential_id' => array('type' => 'ascii','precision' => '255','nullable' => False),
			'pubkey_json' => array('type' => 'varchar','meta' => 'json','precision' => '8192','nullable' => False),
			'pubkey_created' => array('type' => 'timestamp','nullable' => False),
			'pubkey_updated' => array('type' => 'timestamp','nullable' => False,'default' => 'current_timestamp'),
			'account_id' => array('type' => 'int','meta' => 'user','precision' => '4','nullable' => False),
			'pubkey_deleted' => array('type' => 'timestamp','comment' => 'timestamp when pubkey was deleted')
		),
		'pk' => array('pubkey_id'),
		'fk' => array(),
		'ix' => array('pubkey_deleted'),
		'uc' => array('pubkey_credential_id')
	)
);
