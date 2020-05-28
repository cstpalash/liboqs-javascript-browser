const opn = require('opn');
const express = require('express');
const app = express();
var colors = require('colors');
var config = require('./config.js');
var path = require('path');
colors.setTheme({ info:'brightMagenta', highlight:'brightBlue', error:'brightRed', success:'green'});

app.use(express.static('demo/public'));
app.get("/api/qs/crypto", getCrypto);

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