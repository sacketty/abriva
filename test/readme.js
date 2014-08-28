// Load modules

var Lab = require('lab');
var Hoek = require('hoek');
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

    describe('README', function () {

        describe('core', function () {

            var credentials = {
                adr: '18ZXvspTuGR8ac4XF3EHGegy6df93vcVzK',
                key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                algorithm: 'sha256'
            };

            var options = {
                credentials: credentials,
                timestamp: 1353832234,
                nonce: 'j4h3g2',
                ext: 'some-app-ext-data'
            };

            it('should generate a header protocol example', function (done) {

                var header = Abriva.client.header('http://example.com:8000/resource/1?b=1&a=2', 'GET', options).field;

                expect(header).to.equal('Abriva adr="18ZXvspTuGR8ac4XF3EHGegy6df93vcVzK", ts="1353832234", nonce="j4h3g2", ext="some-app-ext-data", mac="Hwvm6HlYWYxP542mZbaqLYHBrxZHbTLnDS90IQ2u1XhCDIT3bDUA+4xQSkitOlTOU94v92VzD8Tg3sjcFUa0ehw="');
                done();
            });

            it('should generate a normalized string protocol example', function (done) {

                var normalized = Abriva.crypto.generateNormalizedString('header', {
                    credentials: credentials,
                    ts: options.timestamp,
                    nonce: options.nonce,
                    method: 'GET',
                    resource: '/resource?a=1&b=2',
                    host: 'example.com',
                    port: 8000,
                    ext: options.ext
                });

                expect(normalized).to.equal('abriva.1.header\n1353832234\nj4h3g2\nGET\n/resource?a=1&b=2\nexample.com\n8000\n\nsome-app-ext-data\n');
                done();
            });

            var payloadOptions = Hoek.clone(options);
            payloadOptions.payload = 'Thank you for flying Abriva';
            payloadOptions.contentType = 'text/plain';

            it('should generate a header protocol example (with payload)', function (done) {

                var header = Abriva.client.header('http://example.com:8000/resource/1?b=1&a=2', 'POST', payloadOptions).field;

                expect(header).to.equal('Abriva adr="18ZXvspTuGR8ac4XF3EHGegy6df93vcVzK", ts="1353832234", nonce="j4h3g2", hash="rz/mHF1PmY+uTK+ggmGjQA1gIRG+YQaZKA/6KAUjnVs=", ext="some-app-ext-data", mac="IIxvCZZkZbZ0QaoH8lZ7vfwPwEKwm9aYq5H6CqzBgKFyY3BXU2UCe/UzbaGIV4VAlcXEQfaEh8TFC95OWlFeR1I="');
                done();
            });

            it('should generate a normalized string protocol example (with payload)', function (done) {

                var normalized = Abriva.crypto.generateNormalizedString('header', {
                    credentials: credentials,
                    ts: options.timestamp,
                    nonce: options.nonce,
                    method: 'POST',
                    resource: '/resource?a=1&b=2',
                    host: 'example.com',
                    port: 8000,
                    hash: Abriva.crypto.calculatePayloadHash(payloadOptions.payload, credentials.algorithm, payloadOptions.contentType),
                    ext: options.ext
                });

                expect(normalized).to.equal('abriva.1.header\n1353832234\nj4h3g2\nPOST\n/resource?a=1&b=2\nexample.com\n8000\nrz/mHF1PmY+uTK+ggmGjQA1gIRG+YQaZKA/6KAUjnVs=\nsome-app-ext-data\n');
                done();
            });
        });
    });
});

