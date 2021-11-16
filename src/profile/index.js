const { Ecies, PrivKey, PubKey, deps  } = require('bsv');
// eslint-disable-next-line no-unused-vars
const HandCashConnectService = require('../api/handcash_connect_service');

/**
 * @typedef {Object} UserPublicProfile
 * @property {string} id
 * @property {string} handle
 * @property {string} paymail
 * @property {string} displayName
 * @property {string} avatarUrl
 * @property {string} localCurrencyCode
 * @property {string} bitcoinUnit
 */

/**
 * @typedef {Object} UserPrivateProfile
 * @property {string} phoneNumber
 * @property {string} email
 */

/**
 * @typedef {Object} UserProfile
 * @property {UserPublicProfile} publicProfile
 * @property {UserPrivateProfile} privateProfile
 */

/**
 * @typedef {Object} EncryptionKeypair
 * @property {string} privateKey
 * @property {string} publicKey
 */

/**
 * @typedef {Object} DataSignature
 * @property {string} publicKey
 * @property {string} signature
 */

module.exports = class Profile {
   /**
    * @param {HandCashConnectService} handCashConnectService
    */
   constructor(handCashConnectService) {
      this.handCashConnectService = handCashConnectService;
   }

   /**
    * @returns {Promise<UserProfile>}
    */
   async getCurrentProfile() {
      return this.handCashConnectService.getCurrentProfile();
   }

   /**
    * @param {Array<String>} handles
    * @returns {Promise<Array<UserPublicProfile>>}
    */
   async getPublicProfilesByHandle(handles) {
      return this.handCashConnectService.getPublicProfilesByHandle(handles)
         .then(result => result.items);
   }

   /**
    * @returns {Promise<UserPublicProfile>}
    */
   async getFriends() {
      return this.handCashConnectService.getUserFriends()
         .then(result => result.items);
   }

   /**
    * @returns {Promise<String>}
    */
   async getPermissions() {
      return this.handCashConnectService.getUserPermissions()
         .then(result => result.items);
   }

   /**
    * @returns {Promise<EncryptionKeypair>}
    */
   async getEncryptionKeypair() {
      const privateKey = PrivKey.fromRandom();
      const encryptedKeypair = await this.handCashConnectService.getEncryptionKeypair(
         PubKey.fromPrivKey(privateKey).toString(),
      );

      return {
         pubkey: Ecies.electrumDecrypt(deps.Buffer.from(encryptedKeypair.encryptedPublicKeyHex, 'hex'), privateKey)
            .toString(),
         privkey: Ecies.electrumDecrypt(deps.Buffer.from(encryptedKeypair.encryptedPrivateKeyHex, 'hex'), privateKey)
            .toString(),
      };
   }

   /**
   * @param {Object} dataSignatureParameters
   * @param {String} dataSignatureParameters.value
   * @param {String} dataSignatureParameters.format
   * @returns {Promise<DataSignature>}
   */
   async signData(dataSignatureParameters) {
      return this.handCashConnectService.signData(dataSignatureParameters);
   }
};
