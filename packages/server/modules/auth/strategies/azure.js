/* istanbul ignore file */
'use strict'

const passport = require('passport')
const OIDCStrategy = require('passport-azure-ad').OIDCStrategy
const Strategy  = require('passport-azure-ad').Strategy
const URL = require( 'url' ).URL
const appRoot = require( 'app-root-path' )
const { findOrCreateUser } = require( `${appRoot}/modules/core/services/users` )
//const { getApp, createAuthorizationCode, createAppTokenFromAccessCode } = require( '../services/apps' )


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
      identityMetadata: process.env.AZUREAD_IDENTITY_METADATA,// "https://login.microsoftonline.com/<tenantidguid>/v2.0/.well-known/openid-configuration",
      clientID: process.env.AZUREAD_CLIENT_ID,
      responseType: 'code id_token',
      responseMode: 'form_post',
      issuer: process.env.AZUREAD_TENANT,
      redirectUrl: strategy.callbackUrl,
      allowHttpForRedirectUrl: true,
      clientSecret: process.env.AZUREAD_CLIENT_SECRET,
      scope: [ 'profile', 'email', 'openid'],
      //loggingLevel: "info",
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
    app.get( '/auth/azure/callback', session, passport.authenticate( 'azuread-openidconnect', { failureRedirect: '/auth/error' } ), finalizeAuth )
  
    return strategy
  }

//const cryptoRandomString = require('crypto-random-string')
//const jwt = require('jsonwebtoken')

//const winston = require('../../../config/logger')
//const User = require('../../../models/User')
/*
module.exports = {
    init(app, sessionMiddleware, redirectCheck, handleLogin) {

        if (process.env.USE_AZUREAD !== 'true')
            return null

        // define and set strategy
        let strategy = new OIDCStrategy({
            identityMetadata: process.env.AZUREAD_IDENTITY_METADATA,
            clientID: process.env.AZUREAD_CLIENT_ID,
            responseType: 'code id_token',
            responseMode: 'form_post',
            redirectUrl: new URL('/signin/azure/callback', process.env.CANONICAL_URL).toString(),
            allowHttpForRedirectUrl: true,
            clientSecret: process.env.AZUREAD_CLIENT_SECRET,
            scope: ['profile', 'email', 'openid'],
            // passReqToCallback: true
        }, async (iss, sub, profile, done) => {
            done(null, profile)
        })

        passport.use(strategy)

        app.get('/signin/azure',
            sessionMiddleware,
            redirectCheck,
            passport.authenticate('azuread-openidconnect')
        )

        app.post('/signin/azure/callback',
            sessionMiddleware,
            redirectCheck,
            passport.authenticate('azuread-openidconnect', { failureRedirect: '/signin/error' }),
            async (req, res, next) => {
                if (!req.user) {
                    req.session.errorMessage = 'Failed to retrieve user from the Azure AD auth.'
                    return res.redirect('/signin/error')
                }

                let email = req.user._json.email
                let name = req.user._json.name || req.user.displayName

                if (!name || !email) {
                    req.session.errorMessage = 'Failed to retrieve email and name from the Azure AD auth.'
                    return res.redirect('/signin/error')
                }

                try {
                    let existingUser = await User.findOne({ email: email })

                    // If user exists:
                    if (existingUser) {
                        let userObj = {
                            name: existingUser.name,
                            surname: existingUser.surname,
                            email: existingUser.email,
                            role: existingUser.role,
                            verified: existingUser.verified,
                            token: 'JWT ' + jwt.sign({ _id: existingUser._id, name: existingUser.name, email: existingUser.email }, process.env.SESSION_SECRET, { expiresIn: '24h' }),
                        }

                        existingUser.logins.push({ date: Date.now() })
                        existingUser.markModified('logins')

                        existingUser.providerProfiles['azure'] = req.user._json
                        existingUser.markModified('providerProfiles')

                        await existingUser.save()

                        req.user = userObj
                        return next()
                    }

                    // If user does not exist:
                    let userCount = await User.count({})
                    let myUser = new User({
                        email: email,
                        company: process.env.AZUREAD_ORG_NAME,
                        apitoken: null,
                        role: 'user',
                        verified: true, // If coming from an AD route, we assume the user's email is verified.
                        password: cryptoRandomString({ length: 20, type: 'base64' }), // need a dummy password
                    })

                    myUser.providerProfiles['azure'] = req.user._json
                    myUser.apitoken = 'JWT ' + jwt.sign({ _id: myUser._id }, process.env.SESSION_SECRET, { expiresIn: '2y' })
                    let token = 'JWT ' + jwt.sign({ _id: myUser._id, name: myUser.name, email: myUser.email }, process.env.SESSION_SECRET, { expiresIn: '24h' })

                    if (userCount === 0 && process.env.FIRST_USER_ADMIN === 'true')
                        myUser.role = 'admin'

                    let namePieces = name.split(/(?<=^\S+)\s/)

                    if (namePieces.length === 2) {
                        myUser.name = namePieces[1]
                        myUser.surname = namePieces[0]
                    } else {
                        myUser.name = "Anonymous"
                        myUser.surname = name
                    }

                    await myUser.save()

                    req.user = {
                        name: myUser.name,
                        surname: myUser.surname,
                        email: myUser.email,
                        role: myUser.role,
                        verified: myUser.verified,
                        token: token
                    }
                    return next()
                } catch (err) {
                    winston.error(err)
                    req.session.errorMessage = `Something went wrong. Server said: ${err.message}`
                    return res.redirect('/error')
                }
            },
            handleLogin)

        return {
            strategyName: `Azure AD ${process.env.AZUREAD_ORG_NAME}`,
            signinRoute: '/signin/azure',
            useForm: false
        }
    }
}*/