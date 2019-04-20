const passport = require('passport-strategy');
const util = require('util');
const nJwt = require("njwt");
let initialConfig = require('../../config/config');
const R = require('ramda');

//starts with http:// or https://
const urlStartsWithHTTPOrHTTPS = R.test(/^(http:\/\/|https:\/\/)/);
//starts with '/'
const urlIsRelative = R.test(/^(\/)/);
/**
 * @description tries to deal with relatic
 * @param {string} callbackURL 
 * @param {*}  req
 */
function normalizeCallbackURL(callbackURL,req){
    const startsWithHttpOrHttps = urlStartsWithHTTPOrHTTPS(callbackURL);
    const isRelative = urlIsRelative(callbackURL);
    //callbackURL is relative so we append the host with protocol in the beginnning
     if(!startsWithHttpOrHttps&&isRelative)
        return `${req.protocol}://${req.get('host')}${callbackURL}`;
    //we just add the protocol in the brginning
    else if(!startsWithHttpOrHttps&&!isRelative)
        return `${req.protocol}://${callbackURL}`;
    return callbackURL;
}
const IssuerEncoding = (shragaURL, callbackURL) => `${shragaURL}/${encodeURIComponent(callbackURL)}`;

/**
 * Strategy for shraga authentication
 * @param {*} options @description configuration options
 * @param {*} verify  @description callback verification function.
 */
function Strategy(options, verify) {
    this.name = 'shraga';
    if (typeof options === 'function') {
        verify = options;
        options = {};
    }

    if (!verify)
        throw new Error(`Shraga Authentication Strategy requires a 'verify' function`);

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
    
    if (req.method.toLowerCase() === 'get') {
        console.log('query');
        let callbackURL = options.callbackURL;
        callbackURL = normalizeCallbackURL(callbackURL,req);
        self.redirect(IssuerEncoding(options.shragaURL, options.callbackURL));
    } else if (req.method.toLowerCase() === 'post') {
        console.log("post");
        authenticateJWT(req, validateCallback);
    }

    function verified(err, user, info) {
        if (err) {
            return self.error(err);
        }

        if (!user) {
            return self.fail(info);
        }
        console.log("things");
        self.success(user, info);
    }

    function validateCallback(err, profile) {
        console.log(profile);
        if (err) {
            return self.error(err);
        }
        if (profile) {
            self._verify(profile, verified);
        }
    }

    function authenticateJWT(req, callback) {
        const jwt = req.cookies["jwtUserCreds"];
        nJwt.verify(jwt, Buffer.from(req.cookies["SignInSecret"], 'base64'), (err, verifiedJwt) => {
            if (err) {
                console.error(err);
                return self.error(err);
            } else {
                console.log('getting creds');
                callback(null, verifiedJwt.body);
            }
        })
    }
}

Strategy.prototype.authenticate = authenticate;

module.exports = Strategy;