// Load modules

var Crypto = require('crypto');
var Url = require('url');
var Utils = require('./utils');
var Message = require('./message');
var bc = require('bitcoinjs-lib');

//var util = require('util');
//console.log("bc = "+util.inspect(bc));

var Wallet = bc.Wallet;
var networks = bc.networks;
var eccrypto = bc.crypto;


// Declare internals

var internals = {};

exports.headerCode = 'abriva';


// MAC normalization format version

exports.headerVersion = '1';                        // Prevent comparison of mac values generated with different normalized string formats


// Supported HMAC algorithms

exports.algorithms = ['sha1', 'sha256'];


// Calculate the request MAC

/*
    type: 'header',                                 // 'header', 'bewit', 'response'
    credentials: {
        address: 'zefqerfgzrgstr',
        network: 'bitcoin',
        algorithm: 'sha256'                         // 'sha1', 'sha256'
    },
    options: {
        method: 'GET',
        resource: '/resource?a=1&b=2',
        host: 'example.com',
        port: 8080,
        ts: 1357718381034,
        nonce: 'd3d345f',
        hash: 'U4MKKSmiVxk37JCCrAVIjV/OhB3y+NdwoCr6RShbVkE=',
        ext: 'app-specific-data',
        app: 'hf48hd83qwkj',                        // Application id (Oz)
        dlg: 'd8djwekds9cj'                         // Delegated by application id (Oz), requires options.app
    }
*/

exports.calculateMac = function (type, credentials, options) {
//exports.getDerSignature = function (type, credentials, options) {

    var normalized = exports.generateNormalizedString(type, options);

//    var hmac = Crypto.createHmac(credentials.algorithm, credentials.key).update(normalized);
//    var digest = hmac.digest('base64');
	return exports.getSignature(normalized, credentials);

};


exports.generateNormalizedString = function (type, options) {

    var resource = options.resource || '';
    if (resource &&
        resource[0] !== '/') {

        var url = Url.parse(resource, false);
        resource = url.path;                        // Includes query
    }

    var normalized = exports.headerCode + '.' + exports.headerVersion + '.' + type + '\n' +
                     options.ts + '\n' +
                     options.nonce + '\n' +
                     (options.method || '').toUpperCase() + '\n' +
                     resource + '\n' +
                     options.host.toLowerCase() + '\n' +
                     options.port + '\n' +
                     (options.hash || '') + '\n';

    if (options.ext) {
        normalized += options.ext.replace('\\', '\\\\').replace('\n', '\\n');
    }

    normalized += '\n';

    if (options.app) {
        normalized += options.app + '\n' +
                      (options.dlg || '') + '\n';
    }

    return normalized;
};


exports.calculatePayloadHash = function (payload, algorithm, contentType) {

    var hash = exports.initializePayloadHash(algorithm, contentType);
    hash.update(payload || '');
    return exports.finalizePayloadHash(hash);
};


exports.initializePayloadHash = function (algorithm, contentType) {

    var hash = Crypto.createHash(algorithm);
    hash.update(exports.headerCode+'.' + exports.headerVersion + '.payload\n');
    hash.update(Utils.parseContentType(contentType) + '\n');
    return hash;
};

exports.getSignature = function(message, credentials, network){
	network = network || networks.bitcoin;
	var wallet = exports.getWallet(credentials, network);
	var privKey = wallet.getPrivateKey(0);
	var signature = Message.sign(privKey, message, network);
	return signature.toString('base64');
};

exports.getWallet = function(credentials, network){
	network = network || networks.bitcoin;
    var seed = eccrypto.sha256(credentials.key);
    return new Wallet(seed, network);
};

exports.finalizePayloadHash = function (hash) {

    hash.update('\n');
    return hash.digest('base64');
};


exports.calculateTsMac = function (ts, credentials) {
/*
    var hmac = Crypto.createHmac(credentials.algorithm, credentials.key);
    hmac.update(exports.headerCode+'.' + exports.headerVersion + '.ts\n' + ts + '\n');
    return hmac.digest('base64');
    */
    return ts;
};


exports.timestampMessage = function (credentials, localtimeOffsetMsec) {

    var now = Utils.nowSecs(localtimeOffsetMsec);
    var tsm = exports.calculateTsMac(now, credentials);
    return { ts: now, tsm: tsm };
};
