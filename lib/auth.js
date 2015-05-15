var jwt = require('express-jwt');
var request = require('request');
var _ = require('lodash');

module.exports.authenticate = jwt({
  secret: function(req, header, payload, cb) {
    switch (header.alg) {
    case 'RS256':
    case 'RS384':
    case 'RS512':
      // asymmetric keys
      
      // TODO: Check that issuer is expected and valid
      var url = payload.iss + '.well-known/jwks.json'
      
      // TODO: Cache the results of finding keys to avoid request overhead every API call
      // FIXME: Disableing strictSSL for now to allow self-signed certs from VM.
      //        Add a proper CA here.
      request.get(url, { json: true, strictSSL: false }, function (err, resp, jwks) {
        if (err) {
          return cb(err);
        }
        if (resp.statusCode !== 200) {
          return cb(new Error('Failed to obtain JWKS from ' + payload.iss));
        }
        
        
        // TODO: Make this more resilient to JWKS and tokens that don't indicate
        //       a kid.
        var key = _.find(jwks.keys, function(key) {
          return key.kid == header.kid;
        });
        
        if (!key) {
          return cb(new Error('Failed to obtain signing key used by ' + payload.iss));
        }
        return (null, key);
      });
      break;
    case 'HS256':
    case 'HS384':
    case 'HS512':
      // symmetric keys
      return cb(null, new Buffer(process.env.AUTH0_CLIENT_SECRET, 'base64'));
    default:
      return cb(new Error('Unsupported JWT algorithm: ' + header.alg));
    }
  },
  audience: process.env.AUTH0_CLIENT_ID
});

module.exports.authenticateAdmin = function(req, res, next) {
  if (req.user && req.user.is_admin) {
    next();
  } else {
    var err = new Error('Unauthorized to access this resource.');
    err.status = 403;
    next(err);
  }
};
