var assert = require('assert');
var expect  = require('chai').expect;


var algo = 'FrodoKEM-640-AES';

describe("liboqs", function(){
	this.timeout(10000);

	var server, client;

	var public_key, aes_key_server;

	var aes_key_client, cipher_text;


	it("server should generate public/secret key pair and able to retrieve public-key", function(done){

		server = require("../javascript/liboqs-server.js");
		server["onRuntimeInitialized"] = function(){

			var keyGenerationStatus = server.ccall('GenerateKeyPair', 'number', ['string'], [ algo ]);
			expect(keyGenerationStatus).to.equal(0);

			public_key = server.ccall('GetPublicKey', 'string');
			expect(public_key.length).to.not.equal(0); //base64 encoded public key

			console.log(Buffer.from(public_key, 'base64').length);

			done();
		}

	});

	it("client should encaps with public-key and generate aes key and ciphertext", function(done){

		client = require("../javascript/liboqs-client.js");
		client["onRuntimeInitialized"] = function(){

			var prepareStatus = client.ccall('Prepare', 'number', ['string'], [ algo ]);
			expect(prepareStatus).to.equal(0);

			//Encaps
			var encapsStatus = client.ccall('Encaps', 'number', ['string'], [ public_key ]);
			expect(encapsStatus).to.equal(0);

			//Get AES key and Cipher text - base64 encoded
			aes_key_client = client.ccall('GetAesKey', 'string');
			expect(aes_key_client.length).to.not.equal(0);
			console.log(Buffer.from(aes_key_client, 'base64').length);

			cipher_text = client.ccall('GetCipherText', 'string');
			expect(cipher_text.length).to.not.equal(0);


			done();
		}

	});

	it("server should decaps with secret key and ciphertext and generate the same aes key", function(done){

		var decapsStatus = server.ccall('Decaps', 'number', ['string'], [ cipher_text ]);
		expect(decapsStatus).to.equal(0);

		//Get AES key - base64 encoded
		aes_key_server = server.ccall('GetAesKey', 'string');
		expect(aes_key_server.length).to.not.equal(0);
		console.log(Buffer.from(aes_key_server, 'base64').length);

		//the main test
		expect(aes_key_server).to.equal(aes_key_client);

		done();

	});

	after(function() {
	    server.ccall('Cleanup', 'void');
	    client.ccall('Cleanup', 'void');
	});

	
});
