const opn = require('opn');
const express = require('express');
var bodyParser = require('body-parser');
const app = express();
var colors = require('colors');
var config = require('./config.js');
var path = require('path');
colors.setTheme({ info:'brightMagenta', highlight:'brightBlue', error:'brightRed', success:'green'});

app.use(express.static('demo/public'));
app.use(bodyParser.json());

app.get("/api/qs/crypto", getCrypto);
app.post('/api/qs/sendCipher', sendCipher);


const algo = "FrodoKEM-640-AES";

var qsServer = require('../javascript/liboqs-server.js');
var publicKey = null;

qsServer["onRuntimeInitialized"] = function(){

	var keyGenerationStatus = qsServer.ccall('GenerateKeyPair', 'number', ['string'], [ algo ]);
	
	if(keyGenerationStatus == 0){
		console.log(`Algo : ${algo} => public/secret key pair generation successful`.success);
		publicKey = qsServer.ccall('GetPublicKey', 'string');

		console.log(`Public Key (size:${Buffer.from(publicKey, 'base64').length}) : ${wrap(publicKey, 50)}`.highlight);

		var url = `http://${config.server}:${config.port}`;
		app.listen(config.port, () => console.log(`Demo server is listening at ${url}`.info));

		opn(url);
	}
	else{

		console.log(`Algo : ${algo} => public/secret key pair generation failed`.error);

	}
}

function wrap(input, limit){
	if(input.length <= limit) return input;

	return input.substring(0, limit) + '...';
}


function getCrypto(req, res){
	return res.json({
		err: null,
		data: {
			algo : algo,
			publicKey : publicKey
		}
	});
}

function sendCipher(req, res){

	var ciphertext = req.body.ciphertext;

	var decapsStatus = qsServer.ccall('Decaps', 'number', ['string'], [ ciphertext ]);
	if(decapsStatus != 0){
		res.send({err : "Decaps failed in server", data: null});
	}
	else{
		res.send({err : null, data: { aesKey : qsServer.ccall('GetAesKey', 'string') }});
		qsServer.ccall('CleanupDecaps', 'void');
	}

}

