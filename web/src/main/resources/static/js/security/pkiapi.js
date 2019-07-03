function createQRCode(randomNum, element) {
    var message = {text:　randomNum};
    element.qrcode(message);
}

function randomPassword(size)
{
    var seed = ['A','B','C','D','E','F','G','H','I','J','K','L','M','N','P','Q','R','S','T','U','V','W','X','Y','Z',
        'a','b','c','d','e','f','g','h','i','j','k','m','n','p','Q','r','s','t','u','v','w','x','y','z',
        '2','3','4','5','6','7','8','9'
    ];//数组
    var seedlength = seed.length;//数组长度
    var createPassword = '';
    for (var i=0;i<size;i++) {
        var j = Math.floor(Math.random()*seedlength);
        createPassword += seed[j];
    }
    return createPassword;
}


function createInitialPackage(user, pass) {
    var message = {user: user, password: pass};
    var TPub = getBytesFromStorage("TPub");
    var TimeStampBase64 = generateTimeStamp("SPub");

    var encrypt = new JSEncrypt();
    encrypt.setPublicKey('-----BEGIN PUBLIC KEY-----' + TPub + '-----END PUBLIC KEY-----');
    var RandomSeed = randomPassword(10); // used to generate Kct and iv

    var kct = aesjs.utils.hex.toBytes($.md5(RandomSeed));
    var Kct = encrypt.encrypt(kct); // the Base64 encoded initial vector for encryption
    var iv = aesjs.utils.hex.toBytes(sha256(RandomSeed));
    var IV = encrypt.encrypt(iv); // the Base64 encoded Kct

    storeBytesToStorage("kct", kct);
    storeBytesToStorage("iv", iv);
    return {payload: message, S: TimeStampBase64, K: Kct, iv: IV};
}


function parseInitialResponsePackage(package) {
    var eToken = $.base64.decode(package.EToken);
    var KP = $.base64.decode(package.KP);
    var timeStampEncrypted = $.base64.decode(package.T);

    //decrypt KP to get the Kcpri and Kcpub;
    var kct = getBytesFromStorage("kct");
    var iv = getBytesFromStorage("iv");
    var aesCbc = new aesjs.ModeOfOperation.cbc(kct, iv);
    var decryptedBytes = aesCbc.decrypt(KP);
    var keyPair = $.base64.encode(decryptedBytes).split(";");
    localStorage.setItem("Kcpub", keyPair[0]);
    localStorage.setItem("Kcpri", keyPair[1]);

    // validate timeStamp
    if (!validateTimeStamp(package.T, "Kcpri")) return false;

    // parse token and nonce from eToken
    var encrypt = new JSEncrypt();
    encrypt.setPrivateKey('-----BEGIN PRIVATE KEY-----' + $.base64.decode(keyPair[1]) + '-----END PRIVATE KEY-----');

    var nonceToken = encrypt.decrypt(eToken);
    var nonce = bytesToInt(nonceToken.slice(0, 4));
    var token = nonceToken.slice(4);

    localStorage.setItem("nonce", nonce);
    storeBytesToStorage("token", token);
    return true;
}

function bytesToInt(bytes) {
    bytes = new Int8Array(bytes);
    var int = bytes[3];
    for(var i=2; i>=0; i--) {
        int = (int << 8 | bytes[i]);
    }
    return int;
}

function intToBytes(int) {
    var ints = [];
    for(var i=0; i<4; i++) {
        ints.push((int>>(8*i)) & (0xFF));
    }

    var byteArray = new Int8Array(ints);
    var bytes = [];
    for(i=0; i<4; i++) {
        bytes.push(byteArray[i]);
    }
    return bytes;
}

function getBytesFromStorage(name) {
    return $.base64.decode(localStorage.getItem(name));
}

function storeBytesToStorage(name, value) {
    localStorage.setItem(name, $.base64.encode(value));
}

function generateEToken() {
    var nonce = localStorage.getItem("nonce") + 1;
    localStorage.setItem("nonce", nonce);

    var token = getBytesFromStorage("token");

    var eTokenContent = intToBytes(nonce);
    for(var i=0; i<token.length; i++) {
        eTokenContent.push(token[i]);
    }

    var encrypt = new JSEncrypt();
    var TPub = getBytesFromStorage("TPub");
    encrypt.setPublicKey('-----BEGIN PUBLIC KEY-----' + TPub + '-----END PUBLIC KEY-----');
    var eToken = encrypt.encrypt(nonce);

    return eToken;
}


function generateTimeStamp(key) {
    var key = getBytesFromStorage(key);

    var encrypt = new JSEncrypt();
    encrypt.setPublicKey('-----BEGIN PUBLIC KEY-----' + key + '-----END PUBLIC KEY-----');
    var timeStamp = (new Date()).valueOf();
    var timeStampBase64 = $.base64.encode(encrypt.encrypt(timeStamp)); // The Base64 encoded encrypted timeStamp

    localStorage.setItem("timeStamp", timeStamp);
    return timeStampBase64;
}

function validateTimeStamp(T, key) {
    var key = getBytesFromStorage(key);

    var encrypt = new JSEncrypt();
    encrypt.setPrivateKey('-----BEGIN PRIVATE KEY-----' + key + '-----END PRIVATE KEY-----');
    var timeStamp = bytesToInt(encrypt.decrypt($.base64.decode(T)));
    var localTimeStamp = localStorage.getItem("timeStamp") + 1;
    localStorage.removeItem("timeStamp");
    return timeStamp === localTimeStamp;
}