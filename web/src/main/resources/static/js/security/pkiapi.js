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
    for (i=0;i<size;i++) {
        j = Math.floor(Math.random()*seedlength);
        createPassword += seed[j];
    }
    return createPassword;
}


function createInitialPackage(user, pass) {
    var message = {user: user, password: pass};
    var SPub = getBytesFromStorage("SPub");
    var TPub = getBytesFromStorage("TPub");

    var encrypt = new JSEncrypt();
    encrypt.setPublicKey('-----BEGIN PUBLIC KEY-----' + SPub + '-----END PUBLIC KEY-----');
    var timeStamp = (new Date()).valueOf();
    var TimeStampBase64 = $.base64.encode(encrypt.encrypt(timeStamp)); // The Base64 encoded encrypted timeStamp

    encrypt.setPublicKey('-----BEGIN PUBLIC KEY-----' + TPub + '-----END PUBLIC KEY-----');
    var RandomSeed = randomPassword(10); // used to generate Kct and iv

    var kct = aesjs.utils.hex.toBytes($.md5(RandomSeed));
    var Kct = encrypt.encrypt(kct); // the Base64 encoded initial vector for encryption
    var iv = aesjs.utils.hex.toBytes(sha256(RandomSeed));
    var IV = encrypt.encrypt(iv); // the Base64 encoded Kct

    localStorage.setItem("timeStamp", timeStamp);
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
    var KcpubBase64 = keyPair[0];
    var KcpriBase64 = keyPair[1];

    var encrypt = new JSEncrypt();
    encrypt.setPrivateKey('-----BEGIN PUBLIC KEY-----' + $.base64.decode(KcpriBase64) + '-----END PUBLIC KEY-----');

    //validate the timeStamp
    var timeStamp = bytesToInt(encrypt.decrypt(timeStampEncrypted));
    if (timeStamp !== localStorage.getItem("timeStamp") + 1)
        return false;

    var nounceToken = encrypt.decrypt(eToken);
    var nounce = bytesToInt(nounceToken.slice(0, 4));
    var token = nounceToken.slice(4);

    localStorage.setItem("Kcpub", KcpubBase64);
    localStorage.setItem("Kcpri", KcpriBase64);
    localStorage.setItem("nounce", nounce);
    storeBytesToStorage("token", token);
    return true
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

function generateEToken(eToken) {

}

function parseEToken() {

}