'use strict'

const url = require('url')

const LogoutRequest = require('./handlers/logout-request')
const LoginConsentRequest = require('./handlers/login-consent-request')
const AuthResponseSent = require('./errors/auth-response-sent')

/**
 * Handles host-side authentication logic (this method is dependency injected
 * into the OIDC Provider instance).
 *
 * If the user is already authenticated (their user id is in the session),
 * simply sets the authRequest.subject property and returns the request.
 *
 * Otherwise, if not already authenticated, 302-redirects the user to the
 * /login endpoint.
 *
 * @param authRequest {AuthenticationRequest} Auth request object created inside
 *   an OIDC Provider in its /authorize endpoint handler.
 *
 * @throws {AuthResponseSent} If the user has been redirected to /login
 *
 * @return {AuthenticationRequest}
 */
function authenticate (authRequest) {
  let debug = authRequest.host.debug || console.log.bind(console)

  let webId = authenticatedUser(authRequest)

  if (webId) {
    debug('User is already authenticated as', webId)

    initSubjectClaim(authRequest, webId)
  } else {
    // User not authenticated, send them to login
    debug('User not authenticated, sending to /login')

    redirectToLogin(authRequest)
  }

  return authRequest
}

function redirectToLogin (authRequest) {
  let loginUrl = url.parse('/login')
  loginUrl.query = authRequest.req.query

  console.log('query:', authRequest.req.query)

  loginUrl = url.format(loginUrl)
  authRequest.subject = null

  console.log('redirecting to:', loginUrl)

  authRequest.res.redirect(loginUrl)

  signalResponseSent()
}

function signalResponseSent () {
  throw new AuthResponseSent('User redirected to login')
}

/**
 * Extracts and returns the authenticated user from session, or null if none.
 *
 * @param authRequest {AuthenticationRequest}
 *
 * @return {string|null} Web ID of the authenticated user, or null
 */
function authenticatedUser (authRequest) {
  let session = authRequest.req.session

  if (!session.identified || !session.userId) {
    return null
  }

  return session.userId
}

/**
 * Initializes the authentication request's subject claim from session user id.
 *
 * @param authRequest {AuthenticationRequest} Auth request object created inside
 *   an OIDC Provider in its /authorize endpoint handler.
 */
function initSubjectClaim (authRequest, webId) {
  authRequest.subject = {
    _id: webId  // put webId into the IDToken's subject claim
  }
}

function obtainConsent (authRequest) {
  let debug = authRequest.host.debug || console.error.bind(console)
  let skipConsent = true

  return LoginConsentRequest.handle(authRequest, skipConsent)
    .catch(error => {
      debug('Error in auth Consent step: ', error)
    })
}

function logout (logoutRequest) {
  let debug = console.error.bind(console)

  return LogoutRequest.handle(logoutRequest.req, logoutRequest.res)
    .then(() => logoutRequest)
    .catch(error => {
      debug('Error in auth logout() step: ', error)
    })
}

module.exports = {
  authenticate,
  obtainConsent,
  logout,
  initSubjectClaim,
  authenticatedUser,
  redirectToLogin
}
