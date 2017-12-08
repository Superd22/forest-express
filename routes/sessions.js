'use strict';
/* jshint sub: true */
var jwt = require('jsonwebtoken');
var path = require('../services/path');
var UserAuthenticator = require('../services/user-authenticator');
var VerifyRefreshToken = require('../services/verify-refresh-token');

module.exports = function (app, opts) {

  function refreshAccessToken(request, response) {
    var requestRefreshToken = jwt.verify(request.body.refreshToken, opts.authSecret).token;
    new VerifyRefreshToken(opts, request.body, requestRefreshToken)
      .perform()
      .then(function (result) {
        if (result.status !== 204) {
          response.sendStatus(400);
          return null;
        }
        return new UserAuthenticator(request, opts)
          .perform()
          .then(function (tokens) { response.send(tokens); })
          .catch(function (error) {
            var body;
            if (error && error.message) {
              body = { errors: [{ detail: error.message }] };
            }
            return response.status(401).send(body);
          });
      })
      .catch(function (error) {
        var body;
        if (error && error.message) {
          body = { errors: [{ detail: error.message }] };
        }
        return response.status(401).send(body);
      });
  }

  function verifyAccessToken(request, response) {
    response.sendStatus(204);
  }

  function login(request, response) {
    new UserAuthenticator(request, opts)
      .perform()
      .then(function (tokens) { response.send(tokens); })
      .catch(function (error) {
        var body;
        if (error && error.message) {
          body = { errors: [{ detail: error.message }] };
        }
        return response.status(401).send(body);
      });
  }

  this.perform = function () {
    app.post(path.generate('sessions', opts), login);
    app.post(path.generate('refreshAccessToken', opts), refreshAccessToken);
    app.get(path.generate('verifyAccessToken', opts), verifyAccessToken);
  };
};
