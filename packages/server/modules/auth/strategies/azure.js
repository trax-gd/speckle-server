/* istanbul ignore file */
'use strict'

const passport = require('passport')
const AzureAdOAuth2Strategy = require('passport-azure-ad-oauth2')
const URL = require('url').URL
const appRoot = require('app-root-path')
const { findOrCreateUser } = require(`${appRoot}/modules/core/services/users`)
const jwt = require('jsonwebtoken');


module.exports = (app, session, sessionStorage, finalizeAuth) => {
  const strategy = {
    id: 'azuread-openidconnect',
    name: 'Microsoft Work/School Account',
    icon: 'mdi-microsoft',
    color: 'blue darken-3',
    url: '/auth/azure',
    callbackUrl: (new URL('/auth/azure/callback', process.env.CANONICAL_URL)).toString()
  }

  passport.use(new AzureAdOAuth2Strategy({
    clientID: process.env.AZUREAD_CLIENT_ID,
    clientSecret: process.env.AZUREAD_CLIENT_SECRET,
    callbackURL: strategy.callbackUrl,
    passReqToCallback: true,
    useCommonEndpoint: true,
  },
    async function (req, accessToken, refresh_token, params, profile, done) {
      let tokenData = jwt.decode(params.id_token);
      
      // UPN: UserPrincipalName Not a durable identifier for the user and should not be used to 
      // uniquely identity user information (for example, as a database key). Instead, it's 
      // better to use the user object ID (oid) as a database key. However in this case, we 
      // need an email, and email might be empty
      // Email: This value is included by default if the user is a guest in the tenant. 
      // For managed users (the users inside the tenant), it must be requested through this 
      // optional claim or, on v2.0 only, with the OpenID scope.
      let email = tokenData.email || tokenData.upn;
      let name = tokenData.name;
      let user = { email, name }

      if (req.session.suuid) {
        user.suuid = req.session.suuid
      }
      let myUser = await findOrCreateUser({ user: user, rawProfile: profile })
      return done(null, myUser)

    }));

  app.get(strategy.url, session, sessionStorage, passport.authenticate('azure_ad_oauth2', { failureRedirect: '/auth/error' }))
  app.get('/auth/azure/callback', session, passport.authenticate('azure_ad_oauth2', { failureRedirect: '/auth/error' }), finalizeAuth);


  return strategy
}