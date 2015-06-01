require('babel/register');
require('dotenv').load();
var express = require('express');
var path = require('path');
var logger = require('morgan');
var bodyParser = require('body-parser');

var app = express();

// FIXME: Hack for demo.  Need to rely less on grunt and static assets.
app.get('/', function(req, res, next) {
  if (!req.query.configured) {
    return res.redirect('/connect-to-auth0');
  }
  return next();
});

app.use(bodyParser.json());
app.use(logger('dev'));
app.use(express.static(path.join(__dirname, 'public')));

require('./lib/routes')(app);
require('./lib/errors')(app);

module.exports = app;
