"use strict";

var url = require('url'),
    https = require('https'),
    crypto = require('crypto'),
    defaultEncoding = 'utf8',
    defaultHostPattern = /^sns\.[a-zA-Z0-9\-]{3,}\.amazonaws\.com(\.cn)?$/,
    certCache = {},
    subscriptionControlKeys = ['SubscribeURL', 'Token'],
    subscriptionControlMessageTypes = [
        'SubscriptionConfirmation',
        'UnsubscribeConfirmation'
    ],
    requiredKeys = [
        'Message',
        'MessageId',
        'Timestamp',
        'TopicArn',
        'Type',
        'Signature',
        'SigningCertURL',
        'SignatureVersion'
    ],
    signableKeysForNotification = [
        'Message',
        'MessageId',
        'Subject',
        'SubscribeURL',
        'Timestamp',
        'TopicArn',
        'Type'
    ],
    signableKeysForSubscription = [
        'Message',
        'MessageId',
        'Subject',
        'SubscribeURL',
        'Timestamp',
        'Token',
        'TopicArn',
        'Type'
    ],
    lambdaMessageKeys = {
        'SigningCertUrl': 'SigningCertURL',
        'UnsubscribeUrl': 'UnsubscribeURL'
    };

var hashHasKeys = function (hash, keys) {
    for (var i = 0; i < keys.length; i++) {
        if (!(keys[i] in hash)) {
            return false;
        }
    }

    return true;
};

var indexOf = function (array, value) {
    for (var i = 0; i < array.length; i++) {
        if (value === array[i]) {
            return i;
        }
    }

    return -1;
};

function convertLambdaMessage(message) {
    for (var key in lambdaMessageKeys) {
        if (key in message) {
            message[lambdaMessageKeys[key]] = message[key];
        }
    }

    if ('Subject' in message && message.Subject === null) {
        delete message.Subject;
    }

    return message;
}

var validateMessageStructure = function (message) {
    var valid = hashHasKeys(message, requiredKeys);

    if (indexOf(subscriptionControlMessageTypes, message['Type']) > -1) {
        valid = valid && hashHasKeys(message, subscriptionControlKeys);
    }

    return valid;
};

var validateUrl = function (urlToValidate, hostPattern) {
    var parsed = url.parse(urlToValidate);

    return parsed.protocol === 'https:'
        && parsed.path.substr(-4) === '.pem'
        && hostPattern.test(parsed.host);
};

var getCertificate = function (certUrl, cb) {
    if (certCache.hasOwnProperty(certUrl)) {
        cb(null, certCache[certUrl]);
        return;
    }

    https.get(certUrl, function (res) {
        var chunks = [];

        if(res.statusCode !== 200){
            return cb(new CertificateIrretrievableError());
        }

        res
            .on('data', function (data) {
                chunks.push(data.toString());
            })
            .on('end', function () {
                certCache[certUrl] = chunks.join('');
                cb(null, certCache[certUrl]);
            });
    }).on('error', cb)
};

var validateSignature = function (message, settler, encoding) {
    if (message['SignatureVersion'] !== '1') {
        settler.reject(new SignatureVersionError(message.SignatureVersion));
        return;
    }

    var signableKeys = [];
    if (message.Type === 'SubscriptionConfirmation') {
        signableKeys = signableKeysForSubscription.slice(0);
    } else {
        signableKeys = signableKeysForNotification.slice(0);
    }

    var verifier = crypto.createVerify('RSA-SHA1');
    for (var i = 0; i < signableKeys.length; i++) {
        if (signableKeys[i] in message) {
            verifier.update(signableKeys[i] + "\n"
                + message[signableKeys[i]] + "\n", encoding);
        }
    }

    getCertificate(message['SigningCertURL'], function (err, certificate) {
        if (err) {
            settler.reject(err);
            return;
        }
        try {
            if (verifier.verify(certificate, message['Signature'], 'base64')) {
                settler.resolve(message);
            } else {
                settler.reject(new SignatureInvalidError());
            }
        } catch (e) {
            settler.reject(e);
        }
    });
};

/**
 * A validator for inbound HTTP(S) SNS messages.
 *
 * @constructor
 * @param {RegExp} [hostPattern=/^sns\.[a-zA-Z0-9\-]{3,}\.amazonaws\.com(\.cn)?$/] - A pattern used to validate that a message's certificate originates from a trusted domain.
 * @param {String} [encoding='utf8'] - The encoding of the messages being signed.
 */
function MessageValidator(hostPattern, encoding) {
    this.hostPattern = hostPattern || defaultHostPattern;
    this.encoding = encoding || defaultEncoding;
}

/**
 * A callback to be called by the validator once it has verified a message's
 * signature.
 *
 * @callback validationCallback
 * @param {Error} error - Any error encountered attempting to validate a
 *                          message's signature.
 * @param {Object} message - The validated inbound SNS message.
 */

/**
 * Validates a message's signature and passes it to the provided callback.
 *
 * @param {Object} hash
 * @param {validationCallback} cb
 */
MessageValidator.prototype.validate = function (hash, cb) {

	const settler = new Settler(cb);

    if (typeof hash === 'string') {
        try {
            hash = JSON.parse(hash);
        } catch (err) {
            settler.reject(err);
            return;
        }
    }

    hash = convertLambdaMessage(hash);

    if (!validateMessageStructure(hash)) {
        settler.reject(new MessageKeysMissingError());
        return;
    }

    if (!validateUrl(hash['SigningCertURL'], this.hostPattern)) {
        settler.reject(new InvalidDomainError());
        return;
    }

    validateSignature(hash, settler, this.encoding);
};

class Settler
{
	constructor(callback)
	{
		if (callback)
		{
			this.callback = callback;
		}
		else
		{
			this.promise = new Promise
			(
				(_resolve, _reject) =>
				{
					this.resolve = _resolve;
					this.reject = _reject;
				}
			);
		};
	};
	resolve(message)
	{
		if (this.callback)
		{
			this.callback(null, message);
		}
		else
		{
			this.resolve(message);
		};
	};
	reject(error)
	{
		const executor = this.callback || this.reject;
		executor(error);
	};
};

class ValidationError extends Error
{
	constructor(code, message)
	{
		super(message);
		this.code = code;
	};
};

class MessageKeysMissingError extends ValidationError
{
	constructor()
	{
		const message = 'Message missing required keys';
		super(message);
	};
};

class InvalidDomainError extends ValidationError
{
	constructor()
	{
		const code = 'invalidDomain';
		const message = 'The certificate is located on an invalid domain';
		super(code, message);
	};
};

class CertificateIrretrievableError extends ValidationError
{
	constructor()
	{
		const code = 'certificateIrretrievable';
		const message = 'Certificate could not be retrieved';
		super(code, message);
	};
};

class SignatureVersionError extends ValidationError
{
	constructor(version)
	{
		const code = 'signatureVersion';
		const message = 'The signature version ' + version + ' is not supported';
		super(code, message);
		this.version = version;
	};
};

class SignatureInvalidError extends ValidationError
{
	constructor()
	{
		const code = 'signatureInvalid';
		const message = 'The message signature is invalid';
		super(code, message);
	};
};

module.exports =
{
	MessageValidator,
	ValidationError,
	MessageKeysMissingError,
	InvalidDomainError,
	CertificateIrretrievableError,
	SignatureVersionError,
	SignatureInvalidError
};