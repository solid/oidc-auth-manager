'use strict'

const { URL } = require('whatwg-url')
const validUrl = require('valid-url')
const fetch = require('node-fetch')
const li = require('li')
const rdf = require('rdflib')

module.exports = {
  discoverProviderFor,
  parseProviderLink,
  preferredProviderFor,
  providerExists,
  validateProviderUri
}

/**
 * @param uri {string} Provider URI or Web ID URI
 *
 * @returns {Promise<string>}
 */
function preferredProviderFor (uri) {
  // First, determine if the uri is an OIDC provider
  return providerExists(uri)
    .then(providerUri => {
      if (providerUri) {
        return providerUri // the given uri's origin hosts an OIDC provider
      }

      // Given uri is not a provider (for example, a static Web ID profile URI)
      // Discover its preferred provider
      return discoverProviderFor(uri)
    })
}

/**
 * @param uri {string} Provider URI or Web ID URI
 *
 * @returns {Promise<string|null>} Returns the Provider URI origin if an OIDC
 *   provider exists at the given uri, or `null` if none exists
 */
function providerExists (uri) {
  const providerOrigin = (new URL(uri)).origin
  const providerConfigUri = providerOrigin + '/.well-known/openid-configuration'

  return fetch(providerConfigUri, { method: 'HEAD' })
    .then(result => {
      if (result.ok) {
        return providerOrigin
      }

      return null
    })
}

/**
 *
 * @param webId {string} Web ID URI
 *
 * @returns {Promise<string>} Resolves with the preferred provider uri for the
 *  given Web ID, extracted from Link rel header or profile body. If no
 *  provider URI was found, reject with an error.
 */
function discoverProviderFor (webId) {
  return discoverFromProfile(webId)

    .then(providerFromProfile => providerFromProfile || discoverFromHeaders(webId))

    .then(providerUri => {
      validateProviderUri(providerUri, webId) // Throw an error if empty or invalid

      return providerUri
    })
}

/**
 * @param webId {string}
 *
 * @returns {Promise<string|null>}
 */
function discoverFromHeaders (webId) {
  return fetch(webId, { method: 'OPTIONS' })
    .then(response => {
      if (response.ok) {
        return parseProviderLink(response.headers)
      }

      return null
    })
}

function discoverFromProfile (webId) {
  const store = rdf.graph()

  const fetcher = rdf.fetcher(store)

  return fetcher.load(webId, { force: true })
    .then(response => {
      const providerTerm = rdf.namedNode('http://www.w3.org/ns/solid/terms#oidcIssuer')
      const providerUri = store.anyValue(rdf.namedNode(webId), providerTerm)
      return providerUri
    }, err => {
      const error = new Error(`Could not reach Web ID ${webId} to discover provider`)
      error.cause = err
      error.statusCode = 400
      throw error
    })
}

/**
 * Returns the contents of the OIDC issuer Link rel header.
 *
 * @see https://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery
 *
 * @param headers {Headers} Response headers from an OPTIONS call
 *
 * @return {string}
 */
function parseProviderLink (headers) {
  const links = li.parse(headers.get('link')) || {}

  return links['http://openid.net/specs/connect/1.0/issuer']
}

/**
 * Validates a preferred provider uri (makes sure it's a well-formed URI).
 *
 * @param provider {string} Identity provider URI
 *
 * @throws {Error} If the URI is invalid
 */
function validateProviderUri (provider, webId) {
  if (!provider) {
    const error = new Error(`OIDC issuer not advertised for ${webId}.
    See https://github.com/solid/webid-oidc-spec#authorized-oidc-issuer-discovery`)
    error.statusCode = 400
    throw error
  }

  if (!validUrl.isUri(provider)) {
    const error = new Error(`OIDC issuer for ${webId} is not a valid URI: ${provider}`)
    error.statusCode = 400
    throw error
  }
}
