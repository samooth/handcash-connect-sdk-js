const HandCashConnectService = require('../api/handcash_connect_service');
const HttpRequestFactory = require('../api/http_request_factory');
const Environments = require('../environments');

module.exports = class HandCashOwner {
   /**
    * @param {HandCashConnectService} handCashConnectService
    */
   constructor(handCashConnectService) {
      /**
       * @property {typeof HandCashConnectService}
       */
      this.handCashConnectService = handCashConnectService;
   }

   /**
    * @param {string} authToken
    * @param {Environment} [env]
    * @param {string} [appSecret]
    * @returns {HandCashOwner}
    */
   static fromAuthToken(authToken,
      /* istanbul ignore next */ env = Environments.prod,
      /* istanbul ignore next */ appSecret = '') {
      const handCashConnectService = new HandCashConnectService(
         new HttpRequestFactory(
            authToken,
            env.apiEndpoint,
            appSecret,
         ),
      );
      return new HandCashOwner(handCashConnectService);
   }

   /**
    * @param {string} alias
    * @param {Array<Object>} locks
    * @returns {string}
    */
   async nextOwner(alias) {
      const res = await this.handCashConnectService.ownerNextAddress(alias);
      return res.ownerAddress;
   }

   /**
    * @param {string} rawTransaction
    * @param {Array<Object>} inputParents
    * @param {Array<Object>} locks
    * @returns {string}
    */
   async sign(rawTransaction, inputParents, locks) {
      const res = await this.handCashConnectService.ownerSign(rawTransaction, inputParents, locks);
      return res.signedTransaction;
   }
};
