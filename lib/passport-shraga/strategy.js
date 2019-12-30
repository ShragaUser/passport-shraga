const passport = require("passport-strategy");
const util = require("util");
const nJwt = require("njwt");
const secureRandom = require("secure-random");
let initialConfig = require("../../config/config");
const R = require("ramda");

//checks http request verb/method
const requestVerbIsGet = req => req.method.toLowerCase() === "get";
const requestVerbIsPost = req => req.method.toLowerCase() === "post";
//checks if a func is a function
const isFunction = func => func instanceof Function;

const generateRandomBuffer = () =>
  secureRandom(256, {
    type: "Buffer"
  });
const generateBase64SigningKey = () =>
  generateRandomBuffer().toString("base64");

//generates default signKey if none was given.
//if signKey is passed as a function returns result of said function else return given value.
const signInKey = (signKey = generateBase64SigningKey) =>
  isFunction(signKey) ? signKey() : signKey;
//transform  profile by transforms object keys
const performTransform = (transform, profile) => {
  let res = {};
  Object.keys(transform).forEach(key => (res[key] = profile[transform[key]]));
  return res;
};
//starts with http:// or https://
const urlStartsWithHTTPOrHTTPS = R.test(/^(http:\/\/|https:\/\/)/);
//starts with '/'
const urlIsRelative = R.test(/^(\/)/);
/**
 * @description tries to deal with relatic
 * @param {string} callbackURL
 * @param {*}  req
 */
function normalizeCallbackURL(callbackURL, req) {
  const startsWithHttpOrHttps = urlStartsWithHTTPOrHTTPS(callbackURL);
  const isRelative = urlIsRelative(callbackURL);
  //callbackURL is relative so we append the host with protocol in the beginnning
  if (!startsWithHttpOrHttps && isRelative)
    return `${req.protocol}://${req.get("host")}${callbackURL}`;
  //we just add the protocol in the brginning
  else if (!startsWithHttpOrHttps && !isRelative)
    callbackURL = `${req.protocol}://${callbackURL}`;
  return callbackURL;
}

const IssuerEncoding = (shragaURL, callbackURL, SignInSecret, useEnrichId, RelayState) =>
  (RelayState ?
    `${shragaURL}/setCallback/${encodeURIComponent(
      callbackURL
    )}?SignInSecret=${encodeURIComponent(SignInSecret)}&useEnrichId=${useEnrichId}&RelayState=${RelayState}` :
    `${shragaURL}/setCallback/${encodeURIComponent(
      callbackURL
    )}?SignInSecret=${encodeURIComponent(SignInSecret)}&useEnrichId=${useEnrichId}`);

const getRelayState = (req, relayStateOption) => (relayStateOption ? relayStateOption : (req.query ? (req.query.RelayState || null) : null));

/**
 * Strategy for shraga authentication
 * @param {*} options @description configuration options
 * @param {*} verify  @description callback verification function.
 */
function Strategy(options, verify) {
  this.name = "shraga";
  if (typeof options === "function") {
    verify = options;
    options = {};
  }

  if (!verify)
    throw new Error(
      `Shraga Authentication Strategy requires a 'verify' function`
    );

  //use default options from config.js and if options are provided via
  //passport initialization override these those fields
  options = {
    ...initialConfig,
    ...options
  };

  passport.Strategy.call(this);

  this._verify = verify;
  this._options = options;
}

util.inherits(Strategy, passport.Strategy);

function authenticate(req, options) {
  let self = this;
  options = {
    ...self._options,
    ...options
  };

  if (requestVerbIsGet(req)) {
    //if its a GET request then redirect the user to adfs-proxy
    //with callback url configured in options
    let callbackURL = normalizeCallbackURL(options.callbackURL, req);
    const signKey = signInKey(options.signKey);
    req.res.cookie("SignInSecret", signKey);
    const relayState = getRelayState(req, options.RelayState);
    self.redirect(IssuerEncoding(options.shragaURL, callbackURL, signKey, options.useEnrichId, relayState));
  } else if (requestVerbIsPost(req)) {
    //if its a POST request then this is the callback from saml so we need to
    //validate the callback and generate and return a jwt

    verifyJWT(req, validateCallback);
  }

  function verified(err, user, info) {
    if (err) {
      return self.error(err);
    }

    if (!user) {
      return self.fail(info);
    }

    const { allowedProviders } = options;
    if (allowedProviders && !allowedProviders.includes(user.provider)) {
      return self.fail('Identity Provider not in allowedProviders list');
    }

    self.success(user, info);
  }

  function validateCallback(err, profile) {
    if (err) {
      return self.error(err);
    }
    if (profile) {
      const { transform } = options;
      if (transform)
        profile = isFunction(transform) ?
          options.transform(profile) :
          performTransform(transform, profile);
      self._verify(profile, verified);
    }
  }

  function verifyJWT(req, callback) {
    const {
      jwt
    } = req.query;
    //verify jwt
    nJwt.verify(
      jwt,
      Buffer.from(req.cookies["SignInSecret"], "base64"),
      (err, verifiedJwt) => {
        if (err) {
          console.error(err);
          return self.error(err);
        } else {
          callback(null, verifiedJwt.body);
        }
      }
    );
  }
}

Strategy.prototype.authenticate = authenticate;

module.exports = Strategy;