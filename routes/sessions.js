'use strict';
/* jshint sub: true */
var _ = require('lodash');
var bcrypt = require('bcryptjs');
var jwt = require('jsonwebtoken');
var SuperAgent = require('superagent');
var path = require('../services/path');
var AllowedUsersFinder = require('../services/allowed-users-finder');
var VerifyRefreshToken = require('../services/verify-refresh-token');
var EnvironmentExpirationTime = require('../services/environment-expiration-time');
var uuidV1 = require('uuid/v1');

var forestUrl = process.env.FOREST_URL ||
  'https://forestadmin-server.herokuapp.com';

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

            if (user === undefined) {
              throw new Error();
            }

            return user;
          })
          .then(function (user) {
            return new EnvironmentExpirationTime(opts)
              .perform()
              .then(function (body) {
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
                  expiresIn: body.accessTokenExpiration + ' seconds'
                });

                SuperAgent
                  .post(forestUrl + '/forest/token')
                  .set('Accept', 'application/json')
                  .send({
                    userId: user.id,
                    renderingId: request.body.renderingId,
                    refreshToken: refreshTokenUuid
                  })
                  .end();

                response.send({
                  token: token,
                  refreshToken: refreshToken
                });
              });
          })
          .catch(function (error) {
            var body;
            if (error && error.message) {
              body = { errors: [{ detail: error.message }] };
            }
            return response.status(401).send(body);
          });
      });
  }

  function verifyAccessToken(request, response) {
    response.sendStatus(204);
  }

  function login(request, response) {
    new AllowedUsersFinder(request.body.renderingId, opts)
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

        if (user === undefined) {
          throw new Error();
        }

        return bcrypt.compare(request.body.password, user.password)
          .then(function (isEqual) {
            if (!isEqual) {
              throw new Error();
            }

            return user;
          });
      })
      .then(function (user) {
        SuperAgent
          .get(forestUrl + '/forest/environment/' + opts.envSecret + '/authExpirationTime')
          .end(function(error, result) {
            var authExpirationTime = result.body.accessTokenExpiration;
            var refreshTokenUuid = uuidV1();

            var refreshToken = jwt.sign({
              token: refreshTokenUuid
            }, opts.authSecret, {
              expiresIn: result.body.refreshTokenExpiration + ' seconds'
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

            SuperAgent
              .post(forestUrl + '/forest/token')
              .set('Accept', 'application/json')
              .send({
                userId: user.id,
                renderingId: request.body.renderingId,
                refreshToken: refreshTokenUuid
              })
              .end();

            response.send({
              token: token,
              refreshToken: refreshToken
            });
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

  this.perform = function () {
    app.post(path.generate('sessions', opts), login);
    app.post('/forest/refreshAccessToken', refreshAccessToken);
    app.get('/forest/verifyAccessToken', verifyAccessToken);
  };
};
