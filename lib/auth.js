var jwt = require('express-jwt');
var request = require('request');
var _ = require('lodash');
var passport = require('passport');
var Auth0Strategy = require('passport-auth0');


module.exports.authenticator = passport;

var strategy = new Auth0Strategy({
   domain:       'login0.myauth0.com',
   clientID:     process.env.AUTH0_SETUP_CLIENT_ID,
   clientSecret: process.env.AUTH0_SETUP_CLIENT_SECRET,
   callbackURL:  '/callback',
    skipUserProfile: true  // FIXME: /userinfo endpoint needs to acces id_token now (as well as access_token for backward compat)
  },
  function(accessToken, refreshToken, extraParams, profile, done) {
    console.log('TOKENS!!!');
    console.log(accessToken);
    console.log(extraParams);
    
    /*
    // accessToken is the token to call Auth0 API (not needed in the most cases)
    // extraParams.id_token has the JSON Web Token
    // profile has all the information from the user
    return done(null, profile);
    */
    
    return done(null, true, { token: accessToken });
  }
);

passport.use('auth0-connect', strategy);



var certToPEM = function (cert) {
  cert = cert.match(/.{1,64}/g).join('\n');
  cert = "-----BEGIN CERTIFICATE-----\n" + cert;
  cert = cert + "\n-----END CERTIFICATE-----\n";
  return cert;
};

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
        // TODO: Make this more resilient to keys that don't include x5c
        return cb(null, certToPEM(key.x5c[0]));
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
  //audience: process.env.AUTH0_CLIENT_ID,
  // TODO: Identify SSO api in audience, make configurable
  audience: 'https://login0.myauth0.com/api/v2/',
  algorithms: [ 'RS256','RS384','RS512', 'HS256','HS384','HS512' ]
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
