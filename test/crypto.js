// Load modules

var Lab = require('lab');
var Abriva = require('../lib');


// Declare internals

var internals = {};


// Test shortcuts

var expect = Lab.expect;
var before = Lab.before;
var after = Lab.after;
var describe = Lab.experiment;
var it = Lab.test;


describe('Abriva', function () {

    describe('Crypto', function () {

        describe('#generateNormalizedString', function () {

            it('should return a valid normalized string', function (done) {

                expect(Abriva.crypto.generateNormalizedString('header', {
                    credentials: {
                        key: 'dasdfasdf',
                        algorithm: 'sha256'
                    },
                    ts: 1357747017,
                    nonce: 'k3k4j5',
                    method: 'GET',
                    resource: '/resource/something',
                    host: 'example.com',
                    port: 8080
                })).to.equal('abriva.1.header\n1357747017\nk3k4j5\nGET\n/resource/something\nexample.com\n8080\n\n\n');

                done();
            });

            it('should return a valid normalized string (ext)', function (done) {

                expect(Abriva.crypto.generateNormalizedString('header', {
                    credentials: {
                        key: 'dasdfasdf',
                        algorithm: 'sha256'
                    },
                    ts: 1357747017,
                    nonce: 'k3k4j5',
                    method: 'GET',
                    resource: '/resource/something',
                    host: 'example.com',
                    port: 8080,
                    ext: 'this is some app data'
                })).to.equal('abriva.1.header\n1357747017\nk3k4j5\nGET\n/resource/something\nexample.com\n8080\n\nthis is some app data\n');

                done();
            });

            it('should return a valid normalized string (payload + ext)', function (done) {

                expect(Abriva.crypto.generateNormalizedString('header', {
                    credentials: {
                        key: 'dasdfasdf',
                        algorithm: 'sha256'
                    },
                    ts: 1357747017,
                    nonce: 'k3k4j5',
                    method: 'GET',
                    resource: '/resource/something',
                    host: 'example.com',
                    port: 8080,
                    hash: 'U4MKKSmiVxk37JCCrAVIjV/OhB3y+NdwoCr6RShbVkE=',
                    ext: 'this is some app data'
                })).to.equal('abriva.1.header\n1357747017\nk3k4j5\nGET\n/resource/something\nexample.com\n8080\nU4MKKSmiVxk37JCCrAVIjV/OhB3y+NdwoCr6RShbVkE=\nthis is some app data\n');

                done();
            });
        });
        
        describe('#withBitcoinLibs', function(){
        	it('should generate a signature', function(done){
        		expect(Abriva.crypto.getSignature("message to sign", {
        			key: 'dasdfasdf',
        			algorithm: 'sha256'
        		})).to.equal("IMI1T8k9w2CRHZCVdDriR68PdxFYaqVmwBVsJ4shhMEnWmgUUFO6wD3HYTpA/oggRKCYk2/Ddo5wj+EXP+Gtmeg=");
        		done();
        	});
        });
    });
});

