'use strict'
const appRoot = require( 'app-root-path' )

const redis = require( 'redis' )
const ExpressSession = require( 'express-session' )
const RedisStore = require( 'connect-redis' )( ExpressSession )
const passport = require( 'passport' )
const debug = require( 'debug' )

const sentry = require( `${appRoot}/logging/sentryHelper` )
const { getApp, createAuthorizationCode } = require( './services/apps' )

module.exports = ( app ) => {

  let authStrategies = []

  passport.serializeUser( ( user, done ) => done( null, user ) )
  passport.deserializeUser( ( user, done ) => done( null, user ) )
  app.use( passport.initialize( ) )

  let session = ExpressSession( {
    store: new RedisStore( { client: redis.createClient( process.env.REDIS_URL ) } ),
    secret: process.env.SESSION_SECRET,
    saveUninitialized: false,
    resave: false,
    cookie: { maxAge: 1000 * 60 * 3 } // 3 minutes
  } )

  let sessionStorage = ( req, res, next ) => {
    if ( !req.query.challenge )
      return res.status( 400 ).send( 'Invalid request: no challenge detected.' )

    req.session.challenge = req.query.challenge
    if ( req.query.suuid ) {
      req.session.suuid = req.query.suuid
    }
    next( )
  }

  /*
  Finalizes authentication for the main frontend application.
   */
  let finalizeAuth = async ( req, res, next ) => {
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
  }

  /*
  Strategies initialisation & listing
  */

  let strategyCount = 0

  if ( process.env.STRATEGY_AZUREAD === 'true' ) {
    let azureadStrategy = require( './strategies/azure' )( app, session, sessionStorage, finalizeAuth )
    //console.log('doingAzure', azureadStrategy);
    authStrategies.push( azureadStrategy )
    strategyCount++
  }

  if ( process.env.STRATEGY_GOOGLE === 'true' ) {
    let googStrategy = require( './strategies/google' )( app, session, sessionStorage, finalizeAuth )
    authStrategies.push( googStrategy )
    strategyCount++
  }

  if ( process.env.STRATEGY_GITHUB === 'true' ) {
    let githubStrategy = require( './strategies/github' )( app, session, sessionStorage, finalizeAuth )
    authStrategies.push( githubStrategy )
    strategyCount++
  }

  // Note: always leave the local strategy init for last so as to be able to
  // force enable it in case no others are present.
  if ( process.env.STRATEGY_LOCAL === 'true' || strategyCount === 0 ) {
    let localStrategy = require( './strategies/local' )( app, session, sessionStorage, finalizeAuth )
    authStrategies.push( localStrategy )
  }

  return authStrategies

}
