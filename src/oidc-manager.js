'use strict'

const fs = require('fs-extra')
const path = require('path')
const { URL } = require('whatwg-url')
const validUrl = require('valid-url')
const ResourceAuthenticator = require('@trust/oidc-rs')
const KVPFileStore = require('kvplus-files')
const MultiRpClient = require('solid-multi-rp-client')
const OIDCProvider = require('@trust/oidc-op')
const UserStore = require('./user-store')

const HostAPI = require('./host-api')
const { discoverProviderFor } = require('./preferred-provider')

const DEFAULT_DB_PATH = './db/oidc'

class OidcManager {
  /**
   * @constructor
   * @param options {Object} Options hashmap object
   *
   * @param [options.storePaths] {Object}
   * @param [options.storePaths.multiRpStore] {string}
   * @param [options.storePaths.providerStore] {string}
   * @param [options.storePaths.userStore] {string}
   *
   * Config for OIDCProvider:
   * @param [options.providerUri] {string} URI of the OpenID Connect Provider
   *
   * @param [options.host] {Object} Injected host behavior object
   * @param [options.host.authenticate] {Function}
   * @param [options.host.obtainConsent] {Function}
   * @param [options.host.logout] {Function}
   *
   * Config for MultiRpClient:
   * @param [options.authCallbackUri] {string} e.g. '/api/oidc/rp'
   * @param [options.postLogoutUri] {string} e.g. '/goodbye'
   *
   * Config for UserStore:
   * @param [options.saltRounds] {number} Number of bcrypt password salt rounds
   *
   * @param [options.debug] {Function} Debug function (defaults to console.log)
   */
  constructor (options) {
    this.storePaths = options.storePaths

    this.providerUri = options.providerUri
    this.host = options.host

    this.authCallbackUri = options.authCallbackUri
    this.postLogoutUri = options.postLogoutUri

    this.saltRounds = options.saltRounds

    this.rs = null
    this.clients = null
    this.localRp = null
    this.provider = null
    this.users = null

    this.debug = options.debug || console.log.bind(console)
  }

  /**
   * Factory method, initializes and returns an instance of OidcManager.
   *
   * @param config {Object} Options hashmap object
   *
   * @param [options.debug] {Function} Debug function (defaults to console.log)
   *
   * @param [config.dbPath='./db/oidc'] {string} Folder in which to store the
   *   auth-related collection stores (users, clients, tokens).
   *
   * Config for OIDCProvider:
   * @param config.providerUri {string} URI of the OpenID Connect Provider
   * @param [config.host] {Object} Injected host behavior object,
   *   see `providerFrom()` docstring.
   *
   * Config for MultiRpClient:
   * @param config.authCallbackUri {string}
   * @param config.postLogoutUri {string}
   *
   * Config for UserStore:
   * @param [config.saltRounds] {number} Number of bcrypt password salt rounds
   *
   * @return {OidcManager}
   */
  static from (config) {
    let options = {
      debug: config.debug,
      providerUri: config.providerUri,
      host: config.host,
      authCallbackUri: config.authCallbackUri,
      postLogoutUri: config.postLogoutUri,
      saltRounds: config.saltRounds,
      storePaths: OidcManager.storePathsFrom(config.dbPath)
    }
    let oidc = new OidcManager(options)

    oidc.validate()

    oidc.initMultiRpClient()
    oidc.initRs()
    oidc.initUserStore()
    oidc.initProvider()

    return oidc
  }

  static storePathsFrom (dbPath = DEFAULT_DB_PATH) {
    // Assuming dbPath = 'db/oidc'
    return {
      // RelyingParty client store path (results in 'db/oidc/rp/clients')
      multiRpStore: path.resolve(dbPath, 'rp'),

      // User store path (results in 'db/oidc/user/['users', 'users-by-email'])
      userStore: path.resolve(dbPath, 'users'),

      // Identity Provider store path (db/oidc/op/['codes', 'clients', 'tokens', 'refresh'])
      providerStore: path.resolve(dbPath, 'op')
    }
  }

  validate () {
    if (!this.providerUri) {
      throw new Error('providerUri is required')
    }
    if (!this.authCallbackUri) {
      throw new Error('authCallbackUri is required')
    }
    if (!this.postLogoutUri) {
      throw new Error('postLogoutUri is required')
    }
  }

  /**
   * Initializes on-disk resources required for OidcManager operation
   * (creates the various storage directories), and generates the provider's
   * crypto keychain (either from a previously generated and serialized config,
   * or from scratch).
   *
   * @return {Promise<RelyingParty>} Initialized local RP client
   */
  initialize () {
    return Promise.resolve()
      .then(() => {
        this.initStorage()

        return this.initProviderKeychain()
      })
      .then(() => {
        this.saveProviderConfig()

        return this.initLocalRpClient()
      })
      .catch(this.debug)
  }

  /**
   * Initializes storage collections (creates directories if using
   * on-disk stores, etc).
   * Synchronous.
   */
  initStorage () {
    this.clients.store.backend.initCollections()
    this.provider.backend.initCollections()
    this.users.initCollections()
  }

  initProviderKeychain () {
    if (this.provider.keys) {
      this.debug('Provider keys loaded from config')
    } else {
      this.debug('No provider keys found, generating fresh ones')
    }

    return this.provider.initializeKeyChain(this.provider.keys)
      .then(keys => {
        this.debug('Provider keychain initialized')
      })
  }

  /**
   * Initializes the local Relying Party client (registered to this instance's
   * Provider). This acts as a cache warm up (proactively registers or loads
   * the client from saved config) so that the first API request that comes
   * along doesn't have to pause to do this. More importantly, it's used
   * to store the local RP client for use by the User
   * Consent screen and other components.
   *
   * @return {Promise<RelyingParty>}
   */
  initLocalRpClient () {
    return this.clients.clientForIssuer(this.providerUri)
      .then(localClient => {
        this.debug('Local RP client initialized')

        this.localRp = localClient

        return localClient
      })
      .catch(error => {
        this.debug('Error initializing local RP client: ', error)
      })
  }

  initMultiRpClient () {
    let localRPConfig = {
      'issuer': this.providerUri,
      'redirect_uri': this.authCallbackUri,
      'post_logout_redirect_uris': [ this.postLogoutUri ]
    }

    let backend = new KVPFileStore({
      path: this.storePaths.multiRpStore,
      collections: ['clients']
    })

    let clientOptions = {
      backend,
      debug: this.debug,
      localConfig: localRPConfig
    }

    this.clients = new MultiRpClient(clientOptions)
  }

  initRs () {
    let rsConfig = {  // oidc-rs
      defaults: {
        handleErrors: false,
        optional: true,
        query: true,
        allow: {
          // Restrict token audience to either this serverUri or its subdomain
          audience: (aud) => this.filterAudience(aud)
        }
      }
    }

    this.rs = new ResourceAuthenticator(rsConfig)
  }

  initUserStore () {
    let userStoreConfig = {
      saltRounds: this.saltRounds,
      path: this.storePaths.userStore
    }
    this.users = UserStore.from(userStoreConfig)
  }

  initProvider () {
    let providerConfig = this.loadProviderConfig()
    let provider = new OIDCProvider(providerConfig)
    if (providerConfig.keys) {
      provider.keys = providerConfig.keys
    }

    let backend = new KVPFileStore({
      path: this.storePaths.providerStore,
      collections: ['codes', 'clients', 'tokens', 'refresh']
    })
    provider.inject({ backend })

    // Init the injected host API (authenticate / obtainConsent / logout)
    let host = this.host || {}
    host = Object.assign(host, HostAPI)

    provider.inject({ host })

    this.provider = provider
  }

  providerConfigPath () {
    let storePath = this.storePaths.providerStore

    return path.join(storePath, 'provider.json')
  }

  /**
   * Returns a previously serialized Provider config if one is available on disk,
   * otherwise returns a minimal config object (with just the `issuer` set).
   *
   * @return {Object}
   */
  loadProviderConfig () {
    let providerConfig = {}
    let configPath = this.providerConfigPath()

    let storedConfig = this.loadConfigFrom(configPath)

    if (storedConfig) {
      providerConfig = JSON.parse(storedConfig)
    } else {
      providerConfig.issuer = this.providerUri
    }

    return providerConfig
  }

  /**
   * Loads a provider config from a given path
   *
   * @param path {string}
   *
   * @return {string}
   */
  loadConfigFrom (path) {
    let storedConfig

    try {
      storedConfig = fs.readFileSync(path, 'utf8')
    } catch (error) {
      if (error.code !== 'ENOENT') {
        this.debug('Error in loadConfigFrom: ', error)
        throw error
      }
    }

    return storedConfig
  }

  saveProviderConfig () {
    let configPath = this.providerConfigPath()
    fs.writeFileSync(configPath, JSON.stringify(this.provider, null, 2))
  }

  /**
   * Extracts and verifies the Web ID URI from a set of claims (from the payload
   * of a bearer token).
   *
   * @see https://github.com/solid/webid-oidc-spec#webid-provider-confirmation
   *
   * @param claims {Object} Claims hashmap, typically the payload of a decoded
   *   ID Token.
   *
   * @throws {Error}
   *
   * @returns {Promise<string|null>}
   */
  webIdFromClaims (claims) {
    if (!claims) {
      return Promise.resolve(null)
    }

    const webId = OidcManager.extractWebId(claims)

    const issuer = claims.iss

    const webidFromIssuer = OidcManager.domainMatches(issuer, webId)

    if (webidFromIssuer) {
      // easy case, issuer is in charge of the web id
      return Promise.resolve(webId)
    }

    // Otherwise, verify that issuer is the preferred OIDC provider for the web id
    return discoverProviderFor(webId)
      .then(preferredProvider => {
        if (preferredProvider === issuer) {  // everything checks out
          return webId
        }

        throw new Error(`Preferred provider for Web ID ${webId} does not match token issuer ${issuer}`)
      })
  }

  /**
   * Extracts the Web ID URI from a set of claims (from the payload of a bearer
   * token).
   *
   * @see https://github.com/solid/webid-oidc-spec#deriving-webid-uri-from-id-token
   *
   * @param claims {Object} Claims hashmap, typically the payload of a decoded
   *   ID Token.
   *
   * @param claims.iss {string}
   * @param claims.sub {string}
   *
   * @param [claims.webid] {string}
   *
   * @throws {Error}
   *
   * @returns {string|null}
   */
  static extractWebId (claims) {
    let webId

    if (!claims) {
      throw new Error('Cannot extract Web ID from missing claims')
    }

    const issuer = claims.iss

    if (!issuer) {
      throw new Error('Cannot extract Web ID - missing issuer claim')
    }

    if (!claims.webid && !claims.sub) {
      throw new Error('Cannot extract Web ID - no webid or subject claim')
    }

    if (claims.webid) {
      webId = claims.webid
    } else {
      // Look to the subject claim to extract a webid uri
      if (validUrl.isUri(claims.sub)) {
        webId = claims.sub
      } else {
        throw new Error('Cannot extract Web ID - subject claim is not a valid URI')
      }
    }

    return webId
  }

  filterAudience (aud) {
    if (!Array.isArray(aud)) {
      aud = [ aud ]
    }

    return aud.some(a => OidcManager.domainMatches(this.providerUri, a))
  }

  /**
   * Tests whether a given Web ID uri belongs to the issuer. They must be:
   *   - either from the same domain origin
   *   - or the webid is an immediate subdomain of the issuer domain
   *
   * @param issuer {string}
   * @param webId {string}
   *
   * @returns {boolean}
   */
  static domainMatches (issuer, webId) {
    let match

    try {
      webId = new URL(webId)
      let webIdOrigin = webId.origin  // drop the path

      match = (issuer === webIdOrigin) || OidcManager.isSubdomain(webIdOrigin, issuer)
    } catch (err) {
      match = false
    }

    return match
  }

  /**
   * @param subdomain {string} e.g. Web ID origin (https://alice.example.com)
   * @param domain {string} e.g. Issuer domain (https://example.com)
   *
   * @returns {boolean}
   */
  static isSubdomain (subdomain, domain) {
    subdomain = new URL(subdomain)
    domain = new URL(domain)

    if (subdomain.protocol !== domain.protocol) {
      return false  // protocols must match
    }

    subdomain = subdomain.host  // hostname + port, minus the protocol
    domain = domain.host

    // Chop off the first subdomain (alice.databox.me -> databox.me)
    let fragments = subdomain.split('.')
    fragments.shift()
    let abridgedSubdomain = fragments.join('.')

    return abridgedSubdomain === domain
  }
}

module.exports = OidcManager
module.exports.DEFAULT_DB_PATH = DEFAULT_DB_PATH
