'use strict';
var P = require('bluebird');
var Request = require('superagent');

function VerifyRefreshToken(opts, params, refreshToken) {
  this.perform = function () {
    return new P(function (resolve) {
      Request
        .post(opts.forestUrl + '/forest/verifyRefreshToken')
        .set('Accept', 'application/json')
        .send({
          userId: params.userId,
          renderingId: params.renderingId,
          refreshToken: refreshToken
        })
        .end(function (error, result) {
          resolve(result);
        });
    });
  };
}

module.exports = VerifyRefreshToken;
