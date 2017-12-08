'use strict';
var Request = require('superagent');

function RefreshTokenSender(opts, params) {
  this.perform = function () {
    Request
      .post(opts.forestUrl + '/forest/token')
      .set('Accept', 'application/json')
      .send(params)
      .end();
  };
}

module.exports = RefreshTokenSender;
