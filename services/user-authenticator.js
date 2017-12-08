'use strict';
/* jshint sub: true */
var _ = require('lodash');
var bcrypt = require('bcryptjs');
var jwt = require('jsonwebtoken');
var AllowedUsersFinder = require('../services/allowed-users-finder');
var RefreshTokenSender = require('../services/refresh-token-sender');
var EnvironmentExpirationTime = require('../services/environment-expiration-time');
var uuidV1 = require('uuid/v1');

function UserAuthenticator(request, opts) {
  this.perform = function () {
    return new AllowedUsersFinder(request.body.renderingId, opts)
      .perform()
      .then(function (allowedUsers) {
        if (!opts.authSecret) {
          throw new Error('Your Forest authSecret seems to be missing. Can ' +
            'you check that you properly set a Forest authSecret in the ' +
            'Forest initializer?');
        }

        if (allowedUsers.length === 0) {
          throw new Error('Forest cannot retrieve any users for the project ' +
            'you\'re trying to unlock.');
        }

        var user = _.find(allowedUsers, function (allowedUser) {
          return allowedUser.email === request.body.email;
        });

        if (user === undefined) { throw new Error(); }

        if (request.body.refreshToken) { return user; }

        return bcrypt.compare(request.body.password, user.password)
          .then(function (isEqual) {
            if (!isEqual) {
              throw new Error();
            }

            return user;
          });
      })
      .then(function (user) {
        return new EnvironmentExpirationTime(opts)
          .perform()
          .then(function (body) {
            var authExpirationTime = body.accessTokenExpiration;
            var refreshTokenUuid = uuidV1();
            var refreshToken = jwt.sign({
              token: refreshTokenUuid
            }, opts.authSecret, {
              expiresIn: body.refreshTokenExpiration + ' seconds'
            });
            var token = jwt.sign({
              id: user.id,
              type: 'users',
              data: {
                email: user.email,
                'first_name': user['first_name'],
                'last_name': user['last_name'],
                teams: user.teams
              },
              relationships: {
                renderings: {
                  data: [{
                    type: 'renderings',
                    id: request.body.renderingId
                  }]
                }
              }
            }, opts.authSecret, {
              expiresIn: authExpirationTime + ' seconds'
            });

            new RefreshTokenSender(opts, {
              userId: user.id,
              renderingId: request.body.renderingId,
              refreshToken: refreshTokenUuid
            }).perform();

            return {
              token: token,
              refreshToken: refreshToken
            };
          });
      });
  };
}

module.exports = UserAuthenticator;
