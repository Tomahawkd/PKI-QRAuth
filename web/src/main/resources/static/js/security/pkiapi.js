/**
 * get the SPub and TPub from server, store it in localStorage
 * @param serverUrl the url of the server.
 */
function initialize() {
    localStorage.removeItem("SPub");
    localStorage.removeItem("TPub");
    if (localStorage.getItem("SPub") === null || localStorage.getItem("SPub") === "undefined") {
        $.ajax({
            url: "key/dist/spub",
            type: "get",
            success: function (data) {
                localStorage.setItem("SPub", data);
                console.log("success to get public keys of server");
            },
            error: function () {
                console.log("failed to get public keys of server");
            }
        })
    }

    if (localStorage.getItem("TPub") === null || localStorage.getItem("TPub") === "undefined") {
        $.ajax({
            url: "key/dist/tpub",
            type: "get",
            success: function (data) {
                localStorage.setItem("TPub", data);
                console.log("success to get public keys of server");
            },
            error: function () {
                console.log("failed to get public keys of server");
            }
        })
    }
}


/**
 * generate a QRCode with the QRCodeNonce and place it in QRCodeElement
 * @param QRCodeNonce {string} the nonce displayed in the QRCode
 * @param QRCodeElement the html "div" element used to place the QRCode
 */
function generateQRCode(QRCodeNonce, QRCodeElement) {
    var message = {text: QRCodeNonce};
    QRCodeElement.qrcode(message);
}


/**
 * the function executed when polling to the server
 * @param pollingUrl a url, which the browser polling to
 * @param targetUrl a url, where the page turned to when the polling is successful
 * @param QRCodeElement the html "div" element where the QRCode is placed
 */
function polling(pollingUrl, targetUrl, QRCodeElement) {
    var nonce2 = sessionStorage.getItem("QRCodeNonce");
    var currentStatus = sessionStorage.getItem("currentStatus") ? sessionStorage.getItem("currentStatus") : 0;
    $.ajax({
        url: pollingUrl,
        type: "post",
        contentType: "application/json; charset=utf-8",
        dataType: "json",
        data: JSON.stringify({nonce2: nonce2}),
        success: function (data) {
            var msg = JSON.parse(data.M);
            if (msg.status >= currentStatus) {
                if (msg.status === 0) {
                } else if (data.status === 1) {
                    sessionStorage.setItem("currentStatus", 1);
                    QRCodeElement.innerHTML("<p>已扫描，等待确认</p>");
                } else if (msg.status === 2) {
                    if(validateQRInitialResponsePackage(data)) {
                        sessionStorage.removeItem("QRCodeNonce");
                        sessionStorage.removeItem("currentStatus");
                        window.location.href = targetUrl;
                    } else {
                        sessionStorage.removeItem("currentStatus");
                        QRCodeElement.innerHTML("<p>验证失败，点击刷新</p>");
                    }
                } else {
                    clearInterval(poller);
                    console.log("incorrect status code.");
                }
            } else {
                sessionStorage.removeItem("currentStatus");
                QRCodeElement.innerHTML("<p>状态码错误，点击刷新</p>");
            }
        },
        error: function () {
            clearInterval(poller);
            console.log("unknown fault.");
        }
    })
}


/**
 * a timer, used to polling to the server,(can be visited by the user of the api)
 */
var poller;


/**
 * clear the poller of the QRCode request.
 */
function clearPolling() {
    if (poller) clearInterval(poller);
}

/**
 * used to parse the response package from the server during the login process
 * @param dataPackage {json} the payload of the response package
 * @returns {boolean} return true when there is no fault
 */
function validateQRInitialResponsePackage(dataPackage) {
        var eToken = dataPackage.EToken;
        var Kp = dataPackage.KP;

        //decrypt KP to get the Kcpri and Kcpub;
        console.log(sessionStorage.getItem("iv"));
        var kct = HexString2Bytes(sessionStorage.getItem("kct"));
        var iv = HexString2Bytes(sessionStorage.getItem("iv"));
        sessionStorage.removeItem("kct");
        sessionStorage.removeItem("iv");
        console.log(kct);
        console.log(iv);
        var aesCbc = new aesjs.ModeOfOperation.cbc(kct, iv);
        var keyPair = cbcUnpading(aesCbc.decrypt(HexString2Bytes(b64tohex(Kp))));
        var split = findSplit(keyPair);
        console.log("length" + keyPair.length);
        console.log(keyPair);
        var Kcpub = String.fromCharCode.apply(null, keyPair.slice(0, split));
        var Kcpri = String.fromCharCode.apply(null, keyPair.slice(split+1));
        console.log("key");
        console.log(keyPair.slice(0, split).length);
        console.log(keyPair.slice(split+1).length);

        console.log(Kcpub);
        console.log(Kcpri);
        localStorage.setItem("Kcpub", Kcpub);
        localStorage.setItem("Kcpri", Kcpri);


        // parse token and nonce from eToken
        var encrypt = new JSEncrypt();
        encrypt.setPrivateKey('-----BEGIN RSA PRIVATE KEY-----' + Kcpri + '-----END RSA PRIVATE KEY-----');

        var nonceToken = encrypt.decrypt(eToken);
        var nonce = bytesToInt(HexString2Bytes(nonceToken.substr(0, 8)));
        var token = nonceToken.substr(8);

        console.log(nonce);
        console.log(token);
        localStorage.setItem("nonce", nonce);
        localStorage.setItem("token", token);
        return true;
}


/**
 * the function complete the whole procession during the login with QRCode
 * @param QRCodeUrl the url of the server, to which we get the QRCode.
 * @param pollingUrl pollingUrl a url, which the browser polling to
 * @param targetUrl a url, where the page turned to when the polling is successful
 * @param QRCodeElement the html "div" element where the QRCode is placed
 * @param click_function the function which is executed when the QRCode is clicked, default is to refresh the QRCode.
 */
function QRAuthentation(QRCodeUrl, pollingUrl, targetUrl, QRCodeElement, click_function) {
    if (poller !== null)
        clearInterval(poller);
    QRCodeElement.unbind("click");
    QRCodeElement.click(click_function ? click_function : function () {
        QRAuthentation(QRCodeUrl, pollingUrl, targetUrl, QRCodeElement, click_function);
    });

    generateKctAndIv();
    var encrypt = new JSEncrypt();
    encrypt.setPrivateKey('-----BEGIN PUBLIC KEY-----' + localStorage.getItem("TPub") + '-----END PUBLIC KEY-----');
    var data = {K: encrypt.encrypt(sessionStorage.getItem("kct")), iv: encrypt.encrypt(sessionStorage.getItem("iv"))};
    console.log(data);
    $.ajax({
        url: QRCodeUrl,
        type: "post",
        data: JSON.stringify(data),
        contentType: "application/json; charset=utf-8",
        dataType: "json",
        success: function (data) {
            QRCodeElement.empty();
            decryptNonce2(data.nonce2);
            generateQRCode(sessionStorage.getItem("QRCodeNonce"), QRCodeElement);
            poller = setInterval(function () {
                polling(pollingUrl, targetUrl, QRCodeElement);
            }, 1000);
        },
        error: function () {
            QRCodeElement.innerHTML = "<p>获取二维码失败，点击刷新</p>";
        }
    });
}


/**
 * create a random String at a set length, which is used to create kct and iv for AES CBC mode
 * @param size the length of the string.
 * @returns {string} the string will be used to create kct and iv
 */
function randomPassword(size) {
    var seed = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'm', 'n', 'p', 'Q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
        '2', '3', '4', '5', '6', '7', '8', '9'
    ];//数组
    var seedlength = seed.length;//数组长度
    var createPassword = '';
    for (var i = 0; i < size; i++) {
        var j = Math.floor(Math.random() * seedlength);
        createPassword += seed[j];
    }
    return createPassword;
}


function generateKctAndIv() {
    var RandomSeed = randomPassword(10); // used to generate Kct and iv
    var iv = $.md5(RandomSeed);
    var kct = sha256(RandomSeed);
    console.log(kct.length);
    console.log(iv.length);

    sessionStorage.setItem("kct", kct);
    sessionStorage.setItem("iv", iv);
    console.log("store" + iv);
}


/**
 * generate a package(place as the payload) used to login with username and password
 * @param data the username and password of the user.
 * @returns {{message: json, T: string, K: string, iv: string}} the request package for login
 */
function generateInitialPackage(data) {
    var TPub = localStorage.getItem("TPub");
    var TimeStampBase64 = generateTimeStamp();

    generateKctAndIv();

    var encrypt = new JSEncrypt();
    encrypt.setPublicKey('-----BEGIN PUBLIC KEY-----' + TPub + '-----END PUBLIC KEY-----');
    var kct = sessionStorage.getItem("kct");
    var iv = sessionStorage.getItem("iv");
    console.log("create package" + iv);
    var Kct = encrypt.encrypt(kct); // hex string of initial vector for encryption
    var IV = encrypt.encrypt(iv); // hex string of encoded Kct

    return {payload: JSON.stringify(data), T: TimeStampBase64, K: Kct, iv: IV};
}


/**
 * used to parse the response package from the server during the login process
 * @param dataPackage {json} the payload of the response package
 * @returns {boolean} return true when there is no fault
 */
function validateInitialResponsePackage(dataPackage) {
    var eToken = dataPackage.EToken;
    var Kp = dataPackage.KP;

    //decrypt KP to get the Kcpri and Kcpub;
    console.log(sessionStorage.getItem("iv"));
    var kct = HexString2Bytes(sessionStorage.getItem("kct"));
    var iv = HexString2Bytes(sessionStorage.getItem("iv"));
    sessionStorage.removeItem("kct");
    sessionStorage.removeItem("iv");
    console.log(kct);
    console.log(iv);
    var aesCbc = new aesjs.ModeOfOperation.cbc(kct, iv);
    var keyPair = cbcUnpading(aesCbc.decrypt(HexString2Bytes(b64tohex(Kp))));
    var split = findSplit(keyPair);
    console.log("length" + keyPair.length);
    console.log(keyPair);
    var Kcpub = String.fromCharCode.apply(null, keyPair.slice(0, split));
    var Kcpri = String.fromCharCode.apply(null, keyPair.slice(split+1));
    console.log("key");
    console.log(keyPair.slice(0, split).length);
    console.log(keyPair.slice(split+1).length);

    console.log(Kcpub);
    console.log(Kcpri);
    localStorage.setItem("Kcpub", Kcpub);
    localStorage.setItem("Kcpri", Kcpri);

    // validate timeStamp
    if (!validateTimeStamp(dataPackage.T)) return false;

    console.log("timeStamp success");
    // parse token and nonce from eToken
    var encrypt = new JSEncrypt();
    encrypt.setPrivateKey('-----BEGIN RSA PRIVATE KEY-----' + Kcpri + '-----END RSA PRIVATE KEY-----');

    var nonceToken = encrypt.decrypt(eToken);
    var nonce = bytesToInt(HexString2Bytes(nonceToken.substr(0, 8)));
    var token = nonceToken.substr(8);

    console.log(nonce);
    console.log(token);
    localStorage.setItem("nonce", nonce);
    localStorage.setItem("token", token);
    return true;
}


function decryptNonce2(encryptNonce) {
    var kct = HexString2Bytes(sessionStorage.getItem("kct"));
    var iv = HexString2Bytes(sessionStorage.getItem("iv"));

    var aesCbc = new aesjs.ModeOfOperation.cbc(kct, iv);
    var nonce2 = bytesToInt(cbcUnpading(aesCbc.decrypt(HexString2Bytes(b64tohex(encryptNonce)))));

    sessionStorage.setItem("QRCodeNonce", nonce2);
}


/**
 * convert a byte[4] array to a integer
 * @param bytes a byte array with length 4
 * @returns {int} return a integer
 */
function bytesToInt(bytes) {
    bytes = new Uint8Array(bytes);
    var int = bytes[3];
    for (var i = 2; i >= 0; i--) {
        int = ((int << 8) + bytes[i]);
    }
    return int;
}


/**
 * convert a integer to a byte array
 * @param int the integer
 * @returns {Array} the byte array converted from the integer
 */
function intToBytes(int) {
    var ints = [];
    for (var i = 0; i < 4; i++) {
        ints.push((int >> (8 * i)) & (0xFF));
    }

    var byteArray = new Uint8Array(ints);
    var bytes = [];
    for (i = 0; i < 4; i++) {
        bytes.push(byteArray[i]);
    }
    return bytes;
}


/**
 * read a byte array from the localStorage, such as key, token and so on.
 * @param name the name of the byte array.
 * @returns {*|String} the byte array.
 */
function getBytesFromStorage(name) {
    return $.base64.decode(localStorage.getItem(name));
}


/**
 * store a byte array to localStorage
 * @param name the name of the byte array.
 * @param value the value of the byte array.
 */
function storeBytesToStorage(name, value) {
    localStorage.setItem(name, $.base64.encode(value));
}


/**
 * use the nonce and token in localStorage to generate EToken.
 * @returns {*|String} a EToken
 */
function generateEToken() {
    var nonce = parseInt(localStorage.getItem("nonce")) + 1;
    localStorage.setItem("nonce", nonce);

    var token = localStorage.getItem("token");

    var eTokenContent = Bytes2HexString(intToBytes(nonce)) + token;

    var encrypt = new JSEncrypt();
    var TPub = localStorage.getItem("TPub");
    encrypt.setPublicKey('-----BEGIN PUBLIC KEY-----' + TPub + '-----END PUBLIC KEY-----');

    return encrypt.encrypt(eTokenContent);
}


/**
 * use current Date to generate a timeStamp, store it to localStorage
 * @returns {*|String} the base64 encoded encrypted(with SPub) timeStamp.
 */
function generateTimeStamp() {
    var key = localStorage.getItem("SPub");

    var encrypt = new JSEncrypt();
    encrypt.setPublicKey('-----BEGIN PUBLIC KEY-----' + key + '-----END PUBLIC KEY-----');
    var timeStamp = Math.floor(Math.random()*10000);
    var timeStampBase64 = encrypt.encrypt(Bytes2HexString(intToBytes(timeStamp))); // The Base64 encoded encrypted timeStamp

    sessionStorage.setItem("timeStamp", timeStamp);
    return timeStampBase64;
}


/**
 * validate the timestamp with the last timeStamp
 * @param T the base64 encoded encrypted timeStamp
 * @returns {boolean} return true when the validate is successful
 */
function validateTimeStamp(T) {
    console.log("timeStamp start");
    console.log(T.length);
    var key = localStorage.getItem("Kcpri");

    var encrypt = new JSEncrypt();
    encrypt.setPrivateKey('-----BEGIN RSA PRIVATE KEY-----' + key + '-----END RSA PRIVATE KEY-----');

    console.log("timeStamp");
    console.log(encrypt.decrypt(T));
    console.log(HexString2Bytes(encrypt.decrypt(T)));
    console.log(bytesToInt(HexString2Bytes(encrypt.decrypt(T))));
    var timeStamp = bytesToInt(HexString2Bytes(encrypt.decrypt(T)));
    var localTimeStamp = parseInt(sessionStorage.getItem("timeStamp")) + 1;
    console.log(timeStamp);
    console.log(localTimeStamp);
    console.log(intToBytes(localTimeStamp));
    console.log(Bytes2HexString(intToBytes(localTimeStamp)));
    // sessionStorage.removeItem("timeStamp");
    return timeStamp === localTimeStamp;
}


/**
 * generate the package(place as payload) used for interaction with server
 * @param data the data for usual business logic
 * @returns {{data: *, T: (*|String), EToken: (*|String)}} the packaged package
 */
function generateInteractionPackage(data) {
    var timeStamp = generateTimeStamp();
    var eToken = generateEToken();
    return {payload: JSON.stringify(data), T:timeStamp, EToken: eToken};
}


/**
 * parse the interaction package with server, validate timeStamp
 * @param data the package containing the business data and timeStamp
 * @returns {{}} after passing validation, return the business data
 */
function parseInteractionPackage(data) {
    if (!validateTimeStamp(data.T)) return {};
    return data.data;
}


/**
 * convert a hex string to a byte array
 * @param str the target hex array
 * @returns {*} a byte string
 */
function HexString2Bytes(str) {
    var pos = 0;
    var len = str.length;
    if (len % 2 !== 0) {
        return null;
    }
    len /= 2;
    var arrBytes = [];
    for (var i = 0; i < len; i++) {
        var s = str.substr(pos, 2);
        var v = parseInt(s, 16);
        arrBytes.push(v);
        pos += 2;
    }
    return arrBytes;
}

/**
 * convert a byte array to a hex string
 * @param arrBytes the target byte array
 * @returns {string} a hex string
 */
function Bytes2HexString(arrBytes) {
    var str = "";
    for (var i = 0; i < arrBytes.length; i++) {
        var tmp;
        var num=arrBytes[i];
        if (num < 0) {
            //此处填坑，当byte因为符合位导致数值为负时候，需要对数据进行处理
            tmp =(255+num+1).toString(16);
        } else {
            tmp = num.toString(16);
        }
        if (tmp.length === 1) {
            tmp = "0" + tmp;
        }
        str += tmp;
    }
    return str;
}


var b64map = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
var b64pad = "=";

function hex2b64(h) {
    var i;
    var c;
    var ret = "";
    for (i = 0; i + 3 <= h.length; i += 3) {
        c = parseInt(h.substring(i, i + 3), 16);
        ret += b64map.charAt(c >> 6) + b64map.charAt(c & 63);
    }
    if (i + 1 == h.length) {
        c = parseInt(h.substring(i, i + 1), 16);
        ret += b64map.charAt(c << 2);
    }
    else if (i + 2 == h.length) {
        c = parseInt(h.substring(i, i + 2), 16);
        ret += b64map.charAt(c >> 2) + b64map.charAt((c & 3) << 4);
    }
    while ((ret.length & 3) > 0) {
        ret += b64pad;
    }
    return ret;
}


function cbcUnpading(array) {
    console.log(array);
    var length = array.length;
    if (length & 0x0f !== 0)
        return null;
    var lastByte = array[array.length-1];
    console.log(lastByte);
    var padValue = array[array.length-1] & 0x0ff;
    console.log(padValue);
    if (padValue < 1 || padValue > 0xff)
        return null;

    var start = length - padValue;
    console.log(start);
    if (start < 0)
        return null;

    for (var i = start; i< length; i++)
        if (array[i] !== padValue)
            return null;

    return array.slice(0, start);
}


function b64tohex(s) {
    var ret = "";
    var i;
    var k = 0; // b64 state, 0-3
    var slop = 0;
    for (i = 0; i < s.length; ++i) {
        if (s.charAt(i) == b64pad) {
            break;
        }
        var v = b64map.indexOf(s.charAt(i));
        if (v < 0) {
            continue;
        }
        if (k == 0) {
            ret += int2char(v >> 2);
            slop = v & 3;
            k = 1;
        }
        else if (k == 1) {
            ret += int2char((slop << 2) | (v >> 4));
            slop = v & 0xf;
            k = 2;
        }
        else if (k == 2) {
            ret += int2char(slop);
            ret += int2char(v >> 2);
            slop = v & 3;
            k = 3;
        }
        else {
            ret += int2char((slop << 2) | (v >> 4));
            ret += int2char(v & 0xf);
            k = 0;
        }
    }
    if (k == 1) {
        ret += int2char(slop << 2);
    }
    return ret;
}

var BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz";
function int2char(n) {
    return BI_RM.charAt(n);
}

function findSplit(array) {
    for (var i=0; i<array.length; i++) {
        if (array[i] === 59)
            return i
    }
    return 0;
}