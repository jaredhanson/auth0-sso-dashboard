var auth = require('./auth');
var auth0Service = require('./auth0_service');
var dataService = require('./data_service');
var jwt = require('jsonwebtoken');

module.exports = function(app) {
  
  // FIXME: This shouldn't be necessary if we update to latest passport-oauth2 in passport-auth0
  app.use(auth.authenticator.initialize());
  
  app.get('/api/authorize', function(req, res, next) {
    var token = req.get('Authorization').substring('Bearer '.length);
    console.log(token)
    jwt.verify(token, process.env.AUTH0_CLIENT_SECRET, function(err, decoded) {
      if (err) {
        console.log(err);
        res.sendStatus(403);
      } else {
        console.log(decoded.sub)
        auth0Service.isAuthorized(decoded.sub, decoded.client_id, req.token).then(result => {
          if (result) {
            res.sendStatus(200);
          } else {
            res.sendStatus(403);
          }
        }).catch(next);
      }
    });
  });

  app.use('/api', auth.authenticate,
    function extractToken(req, res, next) {
      if (req.headers && req.headers.authorization) {
        var parts = req.headers.authorization.split(' ');
        if (parts.length == 2) {
          var scheme = parts[0];
          var credentials = parts[1];

          if (/^Bearer$/i.test(scheme)) {
            req.token = credentials;
          }
        }
      }
      next();
    });

  app.get('/api/userapps', function(req, res, next) {
    auth0Service.getAppsForUser(req.user.sub, req.token).then(apps => {
      res.json(apps);
    }).catch(next);
  });

  app.use('/api', auth.authenticateAdmin);

  app.get('/api/apps', function(req, res, next) {
    auth0Service.getApps(req.token).then(apps => {
      res.json(apps);
    }).catch(next);
  });

  app.post('/api/apps', function(req, res, next) {
    dataService.saveClient(req.body).then((client) => {
      res.json(client);
    }).catch(next);
  });

  app.get('/api/roles', function(req, res, next) {
    dataService.getRoles()
    .then((roles) => {
      res.json({ roles: roles });
    }).catch(next);
  });

  app.post('/api/roles', function(req, res, next) {
    dataService.saveRole(req.body).then((role) => {
      res.json(role);
    }).catch(next);
  });

  app.delete('/api/roles/:id', function(req, res, next) {
    dataService.deleteRole(req.params.id).then(() => {
      res.sendStatus(200);
    }).catch(next);
  });

  app.get('/api/users', function(req, res, next) {
    auth0Service.getUsers(req.params, req.token).then(users => {
      res.json(users);
    }).catch(next);
  });

  app.patch('/api/users/:id', function(req, res, next) {
    auth0Service.saveUser(req.params.id, req.body, req.token).then((user) => {
      res.json(user);
    }).catch(next);
  });
  
  app.get('/connect', function(req, res, next) {
    var url = 'https://login0.myauth0.com/authorize';
    url += '?client_id=' + process.env.AUTH0_CLIENT_ID
    url += '&response_type=code'
    url += '&redirect_uri=' + encodeURIComponent('http://localhost:3000/connect-cb');
    url += '&scope=' + encodeURIComponent('create:client');
    
    res.redirect(url);
  });
  
  app.get('/connect-cb', auth.authenticator.authenticate('auth0-connect', { session: false }),
  function(req, res, next) {
    console.log('CREATE A CLIENT HERE!');
    console.log(req.authInfo.token);
    
    // TODO: Use req.authInfo.token to call APIv2 to automatically create a client.
    
    res.redirect('/');
  });
  
};
