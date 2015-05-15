var jwt = require('express-jwt');

module.exports.authenticate = jwt({
  //secret: new Buffer(process.env.AUTH0_CLIENT_SECRET, 'base64'),
  secret: function(req, header, payload, cb) {
    switch (header.alg) {
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
