const passport = require('passport-strategy');
const util = require('util');
const nJwt = require("njwt");
let initialConfig = require('../../config/config');

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
    //TODO: normalize call back url
    const normalizeCallbackURL = (callbackURL) => callbackURL.indexOf('://') > -1 ? callbackURL : callbackURL;
    const IssuerEncoding = (shragaURL, callbackURL) => `${shragaURL}/${encodeURIComponent(normalizeCallbackURL(callbackURL))}`;
    if (req.method.toLowerCase() === 'get') {
        console.log('query');
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