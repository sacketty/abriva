/// Implements Bitcoin's feature for signing arbitrary messages.
var BigInteger = require('bigi')
var bc = require('bitcoinjs-lib');

//var util = require('util');
//console.log("bc = "+util.inspect(bc));

var Wallet = bc.Wallet;
var networks = bc.networks;
var crypto = bc.crypto;
var Address = bc.Address;
var bufferutils = bc.bufferutils;
var ecdsa = bc.ecdsa;
var networks = bc.networks;

var ECPubKey = bc.ECPubKey;
var ECSignature = bc.ECSignature;

var ecurve = require('ecurve')
var ecparams = ecurve.getCurveByName('secp256k1')

function magicHash(message, network) {
  var magicPrefix = new Buffer(network.magicPrefix)
  var messageBuffer = new Buffer(message)
  var lengthBuffer = new Buffer(bufferutils.varIntSize(messageBuffer.length))
  bufferutils.writeVarInt(lengthBuffer, messageBuffer.length, 0)

  var buffer = Buffer.concat([magicPrefix, lengthBuffer, messageBuffer])
  return crypto.hash256(buffer)
}

function sign(privKey, message, network) {
  network = network || networks.bitcoin

  var hash = magicHash(message, network)
  var signature = privKey.sign(hash)
  var e = BigInteger.fromBuffer(hash)
  var i = ecdsa.calcPubKeyRecoveryParam(ecparams, e, signature, privKey.pub.Q)

  return signature.toCompact(i, privKey.pub.compressed)
}

// TODO: network could be implied from address
function verify(address, signature, message, network) {
  if(!Buffer.isBuffer(signature)) {
    signature = new Buffer(signature, 'base64')
  }

  if (address instanceof Address) {
    address = address.toString()
  }

  network = network || networks.bitcoin

  var hash = magicHash(message, network)
  var parsed = ECSignature.parseCompact(signature)
  var e = BigInteger.fromBuffer(hash)
  var Q = ecdsa.recoverPubKey(ecparams, e, parsed.signature, parsed.i)

  var pubKey = new ECPubKey(Q, parsed.compressed)
  return pubKey.getAddress(network).toString() === address
}

module.exports = {
  magicHash: magicHash,
  sign: sign,
  verify: verify
}
