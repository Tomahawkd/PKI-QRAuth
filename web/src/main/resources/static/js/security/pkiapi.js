/**
 * get the SPub and TPub from server, store it in localStorage
 * @param serverUrl the url of the server.
 */
function initialize(serverUrl) {
    if (localStorage.getItem("SPub") === null || localStorage.getItem("TPub") === null) {
        $.ajax({
            url: serverUrl,
            type: "get",
            success: function (data) {
                localStorage.setItem("SPub", data.SPub);
                localStorage.setItem("TPub", data.TPub);
                console.log("success to get public keys of server and Third party");
            },
            error: function () {
                console.log("failed to get public keys of server and Third party");
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
    var nonce = sessionStorage.getItem("QRCodeNonce");
    var currentStatus = sessionStorage.getItem("currentStatus") ? sessionStorage.getItem("currentStorage") : 0;
    $.ajax({
        url: pollingUrl,
        type: "post",
        dataType: "json",
        data: JSON.stringify({nonce: nonce}),
        success: function (data) {
            if (data.status >= currentStatus + 1) {
                if (data.status === 0) {
                } else if (data.status === 1) {
                    sessionStorage.setItem("currentStatus", 1);
                    QRCodeElement.innerHTML("<p>已扫描，等待确认</p>");
                } else if (data.status === 2) {
                    sessionStorage.removeItem("QRCodeNonce");
                    sessionStorage.removeItem("currentStatus");
                    window.location.href = targetUrl;
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
    QRCodeElement.clear("click");
    QRCodeElement.click(click_function ? click_function : function () {
        QRAuthentation(QRCodeUrl, pollingUrl, targetUrl, QRCodeElement, click_function);
    });
    $.ajax({
        url: QRCodeUrl,
        type: "get",
        dataType: "json",
        success: function (data) {
            QRCodeElement.empty();
            sessionStorage.setItem("QRCodeNonce", data.nonce);
            generateQRCode(data.nonce, QRCodeElement);
            poller = setInterval(function () {
                polling(pollingUrl, targetUrl, QRCodeElement);
            }, 1000);
        },
        error: function () {
            QRCodeElement.innerHTML("<p>获取二维码失败，点击刷新</p>");
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


/**
 * generate a package(place as the payload) used to login with username and password
 * @param data the username and password of the user.
 * @returns {{message: json, T: string, K: string, iv: string}} the request package for login
 */
function generateInitialPackage(data) {
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
    return {message: data, T: TimeStampBase64, K: Kct, iv: IV};
}


/**
 * used to parse the response package from the server during the login process
 * @param package {json} the payload of the response package
 * @returns {boolean} return true when there is no fault
 */
function validateInitialResponsePackage(package) {
    var eToken = $.base64.decode(package.EToken);
    var KP = $.base64.decode(package.KP);

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


/**
 * convert a byte[4] array to a integer
 * @param bytes a byte array with length 4
 * @returns {int} return a integer
 */
function bytesToInt(bytes) {
    bytes = new Int8Array(bytes);
    var int = bytes[3];
    for (var i = 2; i >= 0; i--) {
        int = (int << 8 | bytes[i]);
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

    var byteArray = new Int8Array(ints);
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
    var nonce = localStorage.getItem("nonce") + 1;
    localStorage.setItem("nonce", nonce);

    var token = getBytesFromStorage("token");

    var eTokenContent = intToBytes(nonce);
    for (var i = 0; i < token.length; i++) {
        eTokenContent.push(token[i]);
    }

    var encrypt = new JSEncrypt();
    var TPub = getBytesFromStorage("TPub");
    encrypt.setPublicKey('-----BEGIN PUBLIC KEY-----' + TPub + '-----END PUBLIC KEY-----');
    var eToken = encrypt.encrypt(nonce);

    return $.base64.encode(eToken);
}


/**
 * use current Date to generate a timeStamp, store it to localStorage
 * @param key the key used to encrypt the timeStamp
 * @returns {*|String} the base64 encoded encrypted timeStamp.
 */
function generateTimeStamp(key) {
    key = getBytesFromStorage(key);

    var encrypt = new JSEncrypt();
    encrypt.setPublicKey('-----BEGIN PUBLIC KEY-----' + key + '-----END PUBLIC KEY-----');
    var timeStamp = (new Date()).valueOf();
    var timeStampBase64 = $.base64.encode(encrypt.encrypt(intToBytes(timeStamp))); // The Base64 encoded encrypted timeStamp

    localStorage.setItem("timeStamp", timeStamp);
    return timeStampBase64;
}


/**
 * validate the timestamp with the last timeStamp
 * @param T the base64 encoded encrypted timeStamp
 * @param key the key used to decrypt the timeStamp
 * @returns {boolean} return true when the validate is successful
 */
function validateTimeStamp(T, key) {
    key = getBytesFromStorage(key);

    var encrypt = new JSEncrypt();
    encrypt.setPrivateKey('-----BEGIN PRIVATE KEY-----' + key + '-----END PRIVATE KEY-----');
    var timeStamp = bytesToInt(encrypt.decrypt($.base64.decode(T)));
    var localTimeStamp = localStorage.getItem("timeStamp") + 1;
    localStorage.removeItem("timeStamp");
    return timeStamp === localTimeStamp;
}


/**
 * generate the package(place as payload) used for interaction with server
 * @param data the data for usual business logic
 * @returns {{data: *, T: (*|String), EToken: (*|String)}} the packaged package
 */
function generateInteractionPackage(data) {
    var timeStamp = generateTimeStamp("SPub");
    var eToken = generateEToken();
    return {data: data, T:timeStamp, EToken: eToken};
}


/**
 * parse the interaction package with server, validate timeStamp
 * @param data the package containing the business data and timeStamp
 * @returns {{}} after passing validation, return the business data
 */
function parseInteractionPackage(data) {
    if (!validateTimeStamp(data.T, "Kcpri")) return {};
    return data.data;
}