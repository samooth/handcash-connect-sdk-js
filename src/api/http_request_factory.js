const { Hash, Bn, Ecdsa, KeyPair, PubKey, PrivKey, deps } = require('bsv');

const profileEndpoint = '/v1/connect/profile';
const walletEndpoint = '/v1/connect/wallet';

module.exports = class HttpRequestFactory {
   /**
    * @param {string} authToken
    * @param {string} baseApiEndpoint
    */
   constructor(authToken, baseApiEndpoint) {
      this.authToken = authToken;
      this.baseApiEndpoint = baseApiEndpoint;
   }

   _getSignedRequest(method, endpoint, body = {}) {
      const timestamp = new Date().toISOString();
      const privkey = PrivKey.fromBn( Bn.fromBuffer(Buffer.from(this.authToken,"hex")));
      const pubkey = PubKey.fromPrivKey(privkey);
      const serializedBody = JSON.stringify(body) === '{}' ? '' : JSON.stringify(body);
      const rfirma = HttpRequestFactory._getRequestSignature(method, endpoint, serializedBody,
               timestamp, privkey );
      return {
         baseURL: this.baseApiEndpoint,
         url: endpoint,
         method,
         data: serializedBody,
         headers: {
            'oauth-publickey': pubkey.toString(),
            'oauth-signature': HttpRequestFactory._getRequestSignature(method, endpoint, serializedBody,
               timestamp, privkey ),
            'oauth-timestamp': timestamp.toString(),
         },
         responseType: 'json',
      };
   }

   static _getRequestSignature(method, endpoint, serializedBody, timestamp, privkey) {
      const signaturePayload = HttpRequestFactory._getRequestSignaturePayload(method, endpoint,
         serializedBody, timestamp);
      const hash = Hash.sha256( deps.Buffer.from(signaturePayload));
      const keys = new KeyPair().fromPrivKey(privkey);
      return Ecdsa.sign(hash, keys,"little").toString("hex");
   }

   static _getRequestSignaturePayload(method, endpoint, serializedBody, timestamp) {
      return `${method}\n${endpoint}\n${timestamp}\n${serializedBody}`;
   }

   /**
    * @returns {Object}
    */
   getCurrentProfileRequest() {
      return this._getSignedRequest(
         'GET',
         `${profileEndpoint}/currentUserProfile`,
      );
   }

   /**
    * @param {Array<String>} aliases
    * @returns {Object}
    */
   getPublicProfilesByHandleRequest(aliases) {
      return this._getSignedRequest(
         'GET',
         `${profileEndpoint}/publicUserProfiles`,
         {
            aliases,
         },
      );
   }

   /**
    * @returns {Object}
    */
   getUserFriendsRequest() {
      return this._getSignedRequest(
         'GET',
         `${profileEndpoint}/friends`,
      );
   }

   /**
    * @returns {Object}
    */
   getUserPermissionsRequest() {
      return this._getSignedRequest(
         'GET',
         `${profileEndpoint}/permissions`,
      );
   }

   /**
    * @param {String} encryptionPubKey
    * @returns {Object}
    */
   getEncryptionKeypairRequest(encryptionPubKey) {
console.log("getEncryptionKeypairRequest",encryptionPubKey);
      return this._getSignedRequest(
         'GET',
         `${profileEndpoint}/encryptionKeypair`,
         {
            encryptionPubKey
         },
      );
   }

   /**
    * @param {Object} dataSignatureParameters
    * @param {Object} dataSignatureParameters.value
    * @param {Object} dataSignatureParameters.format
    * @returns {Object}
    */
   getDataSignatureRequest(dataSignatureParameters) {
      return this._getSignedRequest(
         'POST',
         `${profileEndpoint}/signData`,
         {
            format: dataSignatureParameters.format,
            value: dataSignatureParameters.value,
         },
      );
   }

   /**
    * @param {String} currencyCode
    * @returns {Object}
    */
   getSpendableBalanceRequest(currencyCode) {
      return this._getSignedRequest(
         'GET',
         `${walletEndpoint}/spendableBalance`,
         {
            currencyCode,
         },
      );
   }

   /**
    * @param {Object} paymentParameters
    * @param {Object} paymentParameters.payments
    * @param {Object} paymentParameters.attachment
    * @param {String} paymentParameters.description
    * @param {String} paymentParameters.appAction
    * @returns {Object}
    */
   getPayRequest(paymentParameters) {
      return this._getSignedRequest(
         'POST',
         `${walletEndpoint}/pay`,
         {
            description: paymentParameters.description,
            appAction: paymentParameters.appAction,
            receivers: paymentParameters.payments,
            attachment: paymentParameters.attachment,
         },
      );
   }

   /**
    * @param {Object} queryParameters
    * @param {Object} queryParameters.transactionId
    * @returns {Object}
    */
   getPaymentRequest(queryParameters) {
      return this._getSignedRequest(
         'GET',
         `${walletEndpoint}/payment`,
         queryParameters,
      );
   }

   /**
    * @param {string} currencyCode
    * @returns {Object}
    */
   getExchangeRateRequest(currencyCode) {
      return this._getSignedRequest(
         'GET',
         `${walletEndpoint}/exchangeRate/${currencyCode}`,
         {},
      );
   }
};
