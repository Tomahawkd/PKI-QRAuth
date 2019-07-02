function createQRCode(randomNum, element) {
    var message = {text:　randomNum};
    element.qrcode(message);
}

function randomPassword(size)
{
    var seed = new Array('A','B','C','D','E','F','G','H','I','J','K','L','M','N','P','Q','R','S','T','U','V','W','X','Y','Z',
        'a','b','c','d','e','f','g','h','i','j','k','m','n','p','Q','r','s','t','u','v','w','x','y','z',
        '2','3','4','5','6','7','8','9'
    );//数组
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
    var SPub = $.base64.decode(localStorage.getItem("SPub"));
    var TPub = $.base64.decode(localStorage.getItem("TPub"));

    var encrypt = new JSEncrypt();
    encrypt.setPublicKey('-----BEGIN PUBLIC KEY-----' + SPub + '-----END PUBLIC KEY-----');
    var timeStamp = (new Date()).valueOf()
    var TimeStampBase64 = $.base64.encode(encrypt.encrypt(timeStamp)); // The Base64 encoded encrypted timeStamp

    encrypt.setPublicKey('-----BEGIN PUBLIC KEY-----' + TPub + '-----END PUBLIC KEY-----');
    var RandomSeed = randomPassword(10); // used to generate Kct and iv

    var kct = $.md5(RandomSeed);
    var Kct = $.base64.encode(encrypt.encrypt(kct)); // the Base64 encoded initial vector for encryption
    var iv = sha256_digest(RandomSeed);
    var IV = $.base64.encode(encrypt.encrypt(iv)); // the Base64 encoded Kct


    localStorage.setItem("kct", kct);
    localStorage.setItem("iv", iv);
    return {payload: message, S: TimeStampBase64, K: Kct, iv: IV};
}


function parseInitialResponsePackage(package) {
    var eToken = $.base64.decode(package.EToken);
    var KP = $.base64.decode(package.KP);
    var timeStamp = $.base64.decode(package.T);

    //decrypt KP to get the Kcpri and Kcpub;
    var kct = localStorage.getItem("kct");
    var iv = localStorage.getItem("iv");
    var aesCbc = new aesjs.ModeOfOperation.cbc(kct, iv);
    var decryptedBytes = aesCbc.decrypt(KP);
    var keyPair = $.base64.encode(decryptedBytes).split(";");
    var KcpubBase64 = keyPair[0];
    var KcpriBase64 = keyPair[1];
    localStorage.setItem("Kcpub", KcpubBase64);
    localStorage.setItem("Kcpri", KcpriBase64);

    var Kcpri = $.base64.decode(KcpriBase64);
    var encrypt = new JSEncrypt();
    encrypt.setPrivateKey('-----BEGIN PUBLIC KEY-----' + Kcpri + '-----END PUBLIC KEY-----');

}

function bytesToInt(bytes) {
    var int = 0;
    for(var i=0; i<4; i++) {
        int += (bytes[i] << (8*i));
    }
    return int;
}

function intToBytes(int) {
    var ints = [];
    for(var i=0; i<4; i++) {
        ints.push((int>>(8*i))%math.pow(2, 7));
    }

    var bytes = new Int8Array(ints);
    return bytes;
}