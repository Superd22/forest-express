'use strict';
var P = require('bluebird');
var request = require('superagent');

function EnvironmentExpirationTime(opts) {
  this.perform = function () {
    return new P(function (resolve) {
      request
        .get(opts.forestUrl + '/forest/environment/' + opts.envSecret + '/authExpirationTime')
        .end(function(error, result) {
          resolve(result.body);
        });
    });
  };
}

module.exports = EnvironmentExpirationTime;
