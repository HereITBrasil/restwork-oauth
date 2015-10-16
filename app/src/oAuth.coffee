jwt = require 'jsonwebtoken'
_ = require 'underscore'
oauth = require 'restify-oauth2'

validClients = null
secretKey = null
tokenValidity = null

grantClientToken = (credentials, req, cb) ->
    client = _.findWhere validClients, credentials
    return cb null, false unless client
    info =
        validResources: client.validResources
    options =
        expiresInMinutes: tokenValidity
        subject: client.secretId
    token = jwt.sign info, secretKey, options
    cb null, token

authenticateToken = (token, req, cb) ->
    jwt.verify token, secretKey, (err, decoded) ->
        return cb null, false if err?
        unless decoded?.validResources?.indexOf(req.route.path) is -1
            return cb null, true
        else
            cb null, false

exports.easyOauth = (server, params) ->
    tokenValidity = params.tokenValidity || 10
    tokenEndpoint = params.endpoint || '/token'
    secretKey = params.secret
    options =
        hooks:
            grantClientToken: (credentials, req, cb) ->
                params.grantClientToken(credentials, req, cb)
            authenticateToken: (token, req, cb) ->
                return cb null, false unless params?.authenticateToken
                params.authenticateToken(credentials, req, cb)
        tokenEndpoint: tokenEndpoint
    oauth.cc server, options