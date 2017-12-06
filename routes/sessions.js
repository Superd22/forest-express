'use strict';
/* jshint sub: true */
var _ = require('lodash');
var bcrypt = require('bcryptjs');
var jwt = require('jsonwebtoken');
var SuperAgent = require('superagent');
var path = require('../services/path');
var AllowedUsersFinder = require('../services/allowed-users-finder');
var uuidV1 = require('uuid/v1');

module.exports = function (app, opts) {

  function refreshAccessToken(request, response) {
    response.json({});
  }

  function verifyAccessToken(request, response) {
    var token = request.headers.authorization.split(' ')[1];
    jwt.verify(token, opts.authSecret, function (err) {
      if (err) { response.status(401).json({ error: err }); }
      else { response.sendStatus(204); }
    });
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
        var forestUrl = process.env.FOREST_URL ||
          'https://forestadmin-server.herokuapp.com';

        SuperAgent
          .get(forestUrl + '/api/environment/' + opts.envSecret + '/authExpirationTime')
          .end(function(error, result) {
            var authExpirationTime = result.body.authExpirationTime || 60 * 60 * 24 * 14;
            var refreshTokenUuid = uuidV1();

            var refreshToken = jwt.sign({
              refreshToken: refreshTokenUuid
            }, opts.authSecret);

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
              .post(forestUrl + '/api/users/setRefreshToken')
              .set('Accept', 'application/json')
              .send({
                userId: user.id,
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
    app.post(path.generate('refreshAccessToken', opts), refreshAccessToken);
    app.get(path.generate('verifyAccessToken', opts), verifyAccessToken);
  };
};
