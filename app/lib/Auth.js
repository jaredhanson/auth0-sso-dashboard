var Dispatcher = require('./Dispatcher');
var Constants = require('./Constants');
var EventEmitter = require('events').EventEmitter;
var API = require('./API');
var CHANGE_EVENT = 'CHANGE';

var Auth = {

  emitter: new EventEmitter(),
  // FIXME: Make it easy to use SSO dashboard with an on-prem or VM deployment
  //lock: new Auth0Lock(__AUTH0_CLIENT_ID__, __AUTH0_DOMAIN__),
  //lock: new Auth0Lock('RLMRJoNVmsoAzn133XceS9azW9KyE1Eb', 'login0.myauth0.com', {
  lock: new Auth0Lock('cli_KaMrHxxLUPFKY4lpdVqBdBzk76Lat1zN', 'login0.myauth0.com', {
        assetsUrl:  'https://sdk.myauth0.com/',
        cdn:        'https://sdk.myauth0.com/'
      }),

  logout: function() {
    this.clearSession();
    Dispatcher.dispatch({
      actionType: Constants.USER_LOGGED_OUT
    });
  },

  clearSession: function() {
    store.remove('id_token');
    store.remove('access_token');
    this.emitChange();
  },

  login: function(callback) {
    this.lock.show({
      authParams: {
        scope: 'openid is_admin'
      },
      closable: false,
      connections: [__AUTH0_CONNECTION__]
    }, (function(err, profile, idToken, accessToken) {
      if (err) {
        // Error callback
        console.log(err);
        throw err;
      } else {
        this.authenticate(profile, idToken, accessToken);
        callback();
      }
    }).bind(this));
  },

  authenticate: function(profile, idToken, accessToken) {
    this.setIdToken(idToken);
    this.setAccessToken(accessToken);
    Dispatcher.dispatch({
      actionType: Constants.RECEIVED_TOKEN_INFO,
      token_info: profile
    });
    Dispatcher.dispatch({
      actionType: Constants.USER_AUTHENTICATED,
      id_token: idToken
    });
  },

  reauthenticate: function() {
    var id_token = this.getIdToken();
    if (id_token) {
      API.loadTokenInfo(id_token);
    }
  },

  setTokenInfo: function(profile) {
    this.token_info = profile;
    this.emitChange();
  },

  getTokenInfo: function() {
    return this.token_info;
  },

  setIdToken: function(id_token) {
    store.set('id_token', id_token);
    this.emitChange();
  },

  getIdToken: function() {
    return store.get('id_token');
  },
  
  setAccessToken: function(token) {
    store.set('access_token', token);
    this.emitChange();
  },

  getAccessToken: function() {
    return store.get('access_token');
  },

  isAuthenticated: function() {
    var id_token = this.getIdToken();
    if (id_token) {
      return true;
    }
    return false;
  },

  emitChange: function() {
    this.emitter.emit(CHANGE_EVENT);
  },

  addChangeListener: function(callback) {
    this.emitter.on(CHANGE_EVENT, callback);
  },

  removeChangeListener: function(callback) {
    this.emitter.removeListener(CHANGE_EVENT, callback);
  }
};

module.exports = Auth;

Dispatcher.register(function(action) {

  switch (action.actionType) {
    case Constants.USER_LOGGED_OUT:
      Auth.clearSession();
      break;
    case Constants.RECEIVED_TOKEN_INFO:
      Auth.setTokenInfo(action.token_info);
      break;
    default:
      // no op
  }
});
