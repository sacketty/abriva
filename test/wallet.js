var assert = require('assert')
var crypto = require('../lib/eccrypto/crypto')
var networks = require('../lib/networks')
//var scripts = require('../lib/scripts')

var Address = require('../lib/address')
var HDNode = require('../lib/eccrypto/hdnode')
var Wallet = require('../lib/wallet')
var util = require('util')

var Lab = require('lab');
// Test shortcuts

var expect = Lab.expect;
var before = Lab.before;
var beforeEach = Lab.beforeEach;
var after = Lab.after;
var describe = Lab.experiment;
var it = Lab.test;

describe('Wallet', function() {
  var seed
  beforeEach(function(done){
    seed = crypto.sha256("don't use a string seed like this in real life")
    done()
  })

  describe('constructor', function() {
    var wallet
    beforeEach(function(done){
      wallet = new Wallet(seed)
      done()
    })

    it('defaults to Bitcoin network', function(done) {
      assert.equal(wallet.getMasterKey().network, networks.bitcoin)
      done()
    })

    it("generates m/0' as the main account", function(done) {
      var mainAccount = wallet.getAccountZero()
      assert.equal(mainAccount.index, 0 + HDNode.HIGHEST_BIT)
      assert.equal(mainAccount.depth, 1)
      done()
    })

    it("generates m/0'/0 as the external account", function(done) {
      var account = wallet.getExternalAccount()
      assert.equal(account.index, 0)
      assert.equal(account.depth, 2)
      done()
    })

    it("generates m/0'/1 as the internal account", function(done) {
      var account = wallet.getInternalAccount()
      assert.equal(account.index, 1)
      assert.equal(account.depth, 2)
      done()
    })

    describe('when seed is not specified', function(){
      it('generates a seed', function(done){
        var wallet = new Wallet()
        assert(wallet.getMasterKey())
        done()
      })
    })

    describe('constructor options', function() {
      beforeEach(function(done) {
        wallet = new Wallet(seed, networks.testnet)
        done()
      })

      it('uses the network if specified', function(done) {
        assert.equal(wallet.getMasterKey().network, networks.testnet)
        done()
      })
    })
  })

  describe('generateAddress', function(){
    it('generate receiving addresses', function(done){
      var wallet = new Wallet(seed, networks.testnet)
      var expectedAddresses = [
        "n1GyUANZand9Kw6hGSV9837cCC9FFUQzQa",
        "n2fiWrHqD6GM5GiEqkbWAc6aaZQp3ba93X"
      ]

      assert.equal(wallet.generateAddress(), expectedAddresses[0])
      assert.equal(wallet.generateAddress(), expectedAddresses[1])
      assert.deepEqual(wallet.addresses, expectedAddresses)
      done()
    })
  })

  describe('generateChangeAddress', function(){
    var wallet
    beforeEach(function(done){
      wallet = new Wallet(seed)
      done()
    })

    it('generates change addresses', function(done){
      var wallet = new Wallet(seed, networks.testnet)
      var expectedAddresses = ["mnXiDR4MKsFxcKJEZjx4353oXvo55iuptn"]

      assert.equal(wallet.generateChangeAddress(), expectedAddresses[0])
      assert.deepEqual(wallet.changeAddresses, expectedAddresses)
      done()
    })
  })

  describe('getPrivateKey', function(){
    var wallet
    beforeEach(function(done){
      wallet = new Wallet(seed)
      done()
    })

    it('returns the private key at the given index of external account', function(done){
      var wallet = new Wallet(seed, networks.testnet)

      assertEqual(wallet.getPrivateKey(0), wallet.getExternalAccount().derive(0).privKey)
      assertEqual(wallet.getPrivateKey(1), wallet.getExternalAccount().derive(1).privKey)
      done()
    })
  })

  describe('getInternalPrivateKey', function(){
    var wallet
    beforeEach(function(done){
      wallet = new Wallet(seed)
      done()
    })

    it('returns the private key at the given index of internal account', function(done){
      var wallet = new Wallet(seed, networks.testnet)
      assertEqual(wallet.getInternalPrivateKey(0), wallet.getInternalAccount().derive(0).privKey)
      assertEqual(wallet.getInternalPrivateKey(1), wallet.getInternalAccount().derive(1).privKey)
      done()
    })
  })

  describe('getPrivateKeyForAddress', function(){
    var wallet
    beforeEach(function(done){
      wallet = new Wallet(seed)
      done()
    })

    it('returns the private key for the given address', function(done){
      var wallet = new Wallet(seed, networks.testnet)
      wallet.generateChangeAddress()
      wallet.generateAddress()
      wallet.generateAddress()

      assertEqual(
        wallet.getPrivateKeyForAddress("n2fiWrHqD6GM5GiEqkbWAc6aaZQp3ba93X"),
        wallet.getExternalAccount().derive(1).privKey
      )
      assertEqual(
        wallet.getPrivateKeyForAddress("mnXiDR4MKsFxcKJEZjx4353oXvo55iuptn"),
        wallet.getInternalAccount().derive(0).privKey
      )
      wallet.generateAddress()
      done()
    })

    it('raises an error when address is not found', function(done){
      var wallet = new Wallet(seed, networks.testnet)

      assert.throws(function() {
        wallet.getPrivateKeyForAddress("n2fiWrHqD6GM5GiEqkbWAc6aaZQp3ba93X")
      }, /Unknown address. Make sure the address is from the keychain and has been generated/)
      done()
    })
  })

  function assertEqual(obj1, obj2){
    assert.equal(obj1.toString(), obj2.toString())
  }

  function assertNotEqual(obj1, obj2){
    assert.notEqual(obj1.toString(), obj2.toString())
  }

  // quick and dirty: does not deal with functions on object
  function cloneObject(obj){
    return JSON.parse(JSON.stringify(obj))
  }
})
