/* istanbul ignore file */
'use strict'

const passport = require('passport')
//const OIDCStrategy = require('passport-azure-ad').OIDCStrategy
const AzureAdOAuth2Strategy  = require('passport-azure-ad-oauth2')
const URL = require( 'url' ).URL
const appRoot = require( 'app-root-path' )
const { findOrCreateUser } = require( `${appRoot}/modules/core/services/users` )
const jwt = require('jsonwebtoken');


module.exports = ( app, session, sessionStorage, finalizeAuth ) => {
    const strategy = {
      id: 'azuread-openidconnect',
      name: 'Azure Active Directory',
      icon: 'mdi-microsoft-azure',
      color: 'blue darken-3',
      url: '/auth/azure',
      callbackUrl: ( new URL( '/auth/azure/callback', process.env.CANONICAL_URL ) ).toString( )
    }

   passport.use(new AzureAdOAuth2Strategy({
      clientID: process.env.AZUREAD_CLIENT_ID,
      clientSecret: process.env.AZUREAD_CLIENT_SECRET,
      callbackURL: strategy.callbackUrl,
      passReqToCallback: true,
      useCommonEndpoint: true,
    },
    async function (req, accessToken, refresh_token, params, profile, done) {
      var profile = jwt.decode(params.id_token);
      let email = profile.upn;
      let name = profile.name;
      let user = { email, name }
      
      if ( req.session.suuid ) {
        user.suuid = req.session.suuid
      }
      let myUser = await findOrCreateUser( { user: user, rawProfile: profile } )
      return done( null, myUser )
      
    }));
    
    app.get( strategy.url, session, sessionStorage, passport.authenticate( 'azure_ad_oauth2', { failureRedirect: '/auth/error' }  ) )
    app.get( '/auth/azure/callback', session, passport.authenticate( 'azure_ad_oauth2', { failureRedirect: '/auth/error' } ), finalizeAuth );
      

    return strategy
  }