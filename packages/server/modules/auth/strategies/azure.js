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
      id: 'azuread',
      name: 'Microsoft Work/School Account',
      icon: 'mdi-microsoft',
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

      let email = profile.upn 
      let name = profile.name
      let user = { email, name }
  
      if ( req.session.suuid ) {
        user.suuid = req.session.suuid
      }
      let myUser = await findOrCreateUser( { user: user } )
      return done( null, myUser )
    } )
  
    passport.use( myStrategy )
  
    app.get( strategy.url, session, sessionStorage, passport.authenticate( 'azuread-openidconnect', { failureRedirect: '/auth/error' }  ) )
    app.get( '/auth/azure/callback', session, passport.authenticate( 'azuread-openidconnect', { failureRedirect: '/auth/error' } ), finalizeAuth );
   
    return strategy
  }