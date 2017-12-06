'use strict';
var P = require('bluebird');
var request = require('superagent');

function EnvironmentExpirationTime(opts) {
  this.perform = function () {
    return new P(function (resolve) {
      var forestUrl = process.env.FOREST_URL ||
        'https://forestadmin-server.herokuapp.com';

      request
        .get(forestUrl + '/forest/environment/' + opts.envSecret + '/authExpirationTime')
        .end(function(error, result) {
          resolve(result.body.authExpirationTime || 60 * 60 * 24 * 14);
        });
    });
  };
}

module.exports = EnvironmentExpirationTime;
