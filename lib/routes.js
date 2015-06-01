var auth = require('./auth');
var auth0Service = require('./auth0_service');
var dataService = require('./data_service');
var jwt = require('jsonwebtoken');
var request = require('request');

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
  
  app.get('/connect-to-auth0', function(req, res, next) {
    var msg = '<h4>Setup SSO Dashboard</h4>'
    msg += '<p>'
    msg += 'In order to use SSO Dashboard, you must first '
    msg += '<a href="/connect">connect</a>'
    msg += ' to your Auth0 domain.'
    msg += '</p>'
    
    res.send(msg);
  });
  
  app.get('/connect', function(req, res, next) {
    var url = 'https://login0.myauth0.com/authorize';
    url += '?client_id=' + process.env.AUTH0_SETUP_CLIENT_ID
    url += '&response_type=code'
    url += '&state=foo'
    url += '&redirect_uri=' + encodeURIComponent('http://localhost:3000/connect-cb');
    url += '&scope=' + encodeURIComponent('openid create:clients');
    
    res.redirect(url);
  });
  
  app.get('/connect-cb', auth.authenticator.authenticate('auth0-connect', { session: false }),
  function(req, res, next) {
    console.log('CREATE A CLIENT HERE!');
    console.log(req.authInfo.token);
    
    // TODO: Use req.authInfo.token to call APIv2 to automatically create a client.
    var body = {
      name: 'SSO Dashboard X',
      callbacks: [
        'http://localhost:3000',
        'http://localhost:3000/connect-cb'
      ],
      "resource_servers": [
        {
          "identifier": 'https://' + process.env.AUTH0_DOMAIN + '/api/v2/',
          "scopes": [ '*' ]
        }
      ]
    }
    
    request({
      method: 'POST',
      url: 'https://' + process.env.AUTH0_DOMAIN + '/api/v2/clients',
      headers: {
        'Authorization': 'Bearer ' + req.authInfo.token
      },
      json: body,
      strictSSL: false
    }, function(error, response, body) {
      console.log('CREATED CLIENT!');
      console.log(error);
      if (response) {
        console.log(response.statusCode)
      }
      console.log(body);
      
      var msg = '<h4>Connected to Auth0!</h4>'
      msg += '<p>'
      msg += 'SSO Dashboard is now connected to Auth0.  Click '
      msg += '<a href="/?configured=true">here</a>'
      msg += ' to continue and login to SSO Dashboard.'
      msg += '</p>'
      
      res.send(msg);
      
      // TODO
      // res.redirect('/');
      
      /*
      if (error || response.statusCode !== 200) {
        return reject(body);
      }
      resolve(body);
      */
    });
    
    
    //res.redirect('/');
  });
  
};
