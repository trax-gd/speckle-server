/* istanbul ignore file */
'use strict'

const passport = require('passport')
const OIDCStrategy = require('passport-azure-ad').OIDCStrategy
const Strategy  = require('passport-azure-ad').Strategy
const URL = require( 'url' ).URL
const appRoot = require( 'app-root-path' )
const { findOrCreateUser } = require( `${appRoot}/modules/core/services/users` )

module.exports = ( app, session, sessionStorage, finalizeAuth ) => {
    const strategy = {
      id: 'azuread-openidconnect',
      name: 'Azure Active Directory',
      icon: 'mdi-microsoft-azure',
      color: 'blue darken-3',
      url: '/auth/azure',
      callbackUrl: ( new URL( '/auth/azure/callback', process.env.CANONICAL_URL ) ).toString( )
    }

    let myStrategy = new OIDCStrategy( {
      identityMetadata: process.env.AZUREAD_IDENTITY_METADATA,
      clientID: process.env.AZUREAD_CLIENT_ID,
      responseType: 'code id_token',
      responseMode: 'form_post',
      issuer: process.env.AZUREAD_TENANT,
      redirectUrl: strategy.callbackUrl,
      allowHttpForRedirectUrl: true,
      clientSecret: process.env.AZUREAD_CLIENT_SECRET,
      scope: [ 'profile', 'email', 'openid'],
      loggingLevel: "info",
      passReqToCallback: true
    }, async ( req, iss, sub, profile, accessToken, refreshToken, done ) => {

      console.log('Azure auth session', req.session);
      console.log('Azure auth iss', iss);
      console.log('Azure auth sub', sub);
      console.log('Azure auth profile', profile);

      let email = profile.emails[ 0 ].value
      let name = profile.displayName
  
      let user = { email, name, avatar: profile._json.picture }
  
      if ( req.session.suuid ) {
        user.suuid = req.session.suuid
      }
  
      let myUser = await findOrCreateUser( { user: user, rawProfile: profile._raw } )
      return done( null, myUser )
    } )
  
    passport.use( myStrategy )
  
    app.get( strategy.url, session, sessionStorage, passport.authenticate( 'azuread-openidconnect', { failureRedirect: '/auth/error' }  ) )
    app.get( '/auth/azure/callback', session, passport.authenticate( 'azuread-openidconnect', { failureRedirect: '/auth/error' } ), async ( req, res, next ) => {
        console.log('testing /auth/azure/callback');
        try {
          let app = await getApp( { id: 'spklwebapp' } )
          let ac = await createAuthorizationCode( { appId: 'spklwebapp', userId: req.user.id, challenge: req.session.challenge } )
    
          if ( req.session ) req.session.destroy( )
          return res.redirect( `${app.redirectUrl}?access_code=${ac}` )
        } catch ( err ) {
          sentry( { err } )
          if ( req.session ) req.session.destroy( )
          return res.status( 401 ).send( 'Invalid request.' )
        }
      } );
  
    return strategy
  }