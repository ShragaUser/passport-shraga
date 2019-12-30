## [Passport-Shraga](https://shragauser.github.io/passport-shraga/#/)
[passport-shraga](https://github.com/ShragaUser/passport-shraga) is a [passport.js](http://www.passportjs.org/) authentication strategy that utilizes [Shraga](https://shragauser.github.io/adfs-proxy-shraga/) as an saml-idp proxy. 

[![npm version](https://badge.fury.io/js/passport-shraga.svg)](https://badge.fury.io/js/passport-shraga)

[![NPM](https://nodei.co/npm/passport-shraga.png)](https://nodei.co/npm/passport-shraga/)

---

### Usage
usage of passport-shraga is as followed:
#### passport.js

```js
const passport = require("passport");
const { Strategy } = require("passport-shraga");

passport.serializeUser((user, cb) => {
    //serialize function
});

passport.deserializeUser((id, cb) => {
    ///deserialize function
});

const config = {};

passport.use(new Strategy(config, (profile, done) => {
    console.log(`My Profile Is: ${profile}`);
    done(null, profile);
}))
```

----

#### In server.js ( express app )

```js
// must be used for passport session
const session = require("express-session");
// must be used so passport can save and use cookies
const cookieParser = require("cookie-parser");
// require passport
const passport = require("passport");
// require code from previous section
const shraga = require("./passport.js");

// app intialization
app.use(cookieParser());
app.use(session({...config}));
app.use(passport.initialize());
app.use(passport.session());
```

----

#### Routes
Two routes must be configured with passport authenticate middleware

```js
app.get('/my/auth/route', passport.authenticate("shraga"), (req,res,next) => {
    // user will not get here and will be redirected to shraga instance configured.
});

app.post('/my/auth/callback/route',  passport.authenticate("shraga"), (req,res,next) => {
    // user will be authenticated and exist in request.
    console.log(req.user);
    res.redirect('/home');
});
```

----

#### Strategy configuration options (1):
```callbackURL```: callback url for Shraga to return the signed JWT. Can be absolute or relative ( ```http://my-domian/path-to-callback``` OR ```/path-to-callback``` )

```shragaURL```: Full URL to the [Shraga](https://shragauser.github.io/adfs-proxy-shraga/) instance running.

```transform```: Function Or Mapping-Object that transforms profile returned from Shraga. 

----

#### Strategy configuration options (2):
```useEnrichId```: (boolean) set to ```true``` if you want Shraga to return user profile with enrichId. set to ```false``` to return user profile with SAML provider id.

```allowedProviders```: Array of allowed identity provider names - if argument is provided only identity providers in this list are allowed to return user profiles. disallowed providers will be followed with authentication failure.

```RelayState```: If RelayState is provided its value will be returned with user profile inside jwtBody ( as 'RelayState' ).

----

##### Transform option:
the tranform option can be configured if early manipulation of the User profile is required. 
transform can ve a function or an object:

----

* in case of ```Function```: the function will recieve the profile and do any manipulation wanted then returns a new profile object to replace current user Profile. example: 
```js
const tranform = (user) => {
  const fullName = `${user.firstName} ${user.lastNmae}`;
  return {...user, fullName};
}
```

----

* in case of Object: the object will act as a mapper and can decide which user properties will be passed on to Authenticate function and under which name they will be passed on as. example:
```js
const transform = {"id": "userId", "firstName":"fname", "lastName":"lname"};
```
the returned object would be: 
```js
{userId: ObjectID, fname: String, lname: String}
```

----

#### RelayState

If 'RelayState' exists in request query params in 'get' method middleware then RelayState option will be set as the value of the query param.

```js
const relayState = req.query.RelayState;
options.RelayState = options.RelayState || relayState; 
```

'RelayState' should be concated to req.path or added ro req.query when you want your application to redirect to the value of req.user.RelayState like the following:

```js
app.use('/auth/shraga', passport.autheticate('shraga'), (req,res,next) => {
    const { RelayState } = req.user;
    res.redirect(`${RelayState}`);
});
```
