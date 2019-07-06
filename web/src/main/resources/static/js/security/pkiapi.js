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
    var currentStatus = sessionStorage.getItem("currentStatus") ? sessionStorage.getItem("currentStatus") : 0;
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
    var TPub = localStorage.getItem("TPub");
    var TimeStampBase64 = generateTimeStamp();

    var encrypt = new JSEncrypt();
    encrypt.setPublicKey('-----BEGIN PUBLIC KEY-----' + TPub + '-----END PUBLIC KEY-----');
    var RandomSeed = randomPassword(10); // used to generate Kct and iv

    var kct = $.md5(RandomSeed);
    var Kct = encrypt.encrypt(kct); // the Base64 encoded initial vector for encryption
    var iv = sha256(RandomSeed);
    var IV = encrypt.encrypt(iv); // the Base64 encoded Kct

    localStorage.setItem("kct", kct);
    localStorage.setItem("iv", iv);
    return {message: data, T: TimeStampBase64, K: Kct, iv: IV};
}


/**
 * used to parse the response package from the server during the login process
 * @param dataPackage {json} the payload of the response package
 * @returns {boolean} return true when there is no fault
 */
function validateInitialResponsePackage(dataPackage) {
    var eToken = $.base64.decode(dataPackage.EToken);
    var Kp = $.base64.decode(dataPackage.Kp);

    //decrypt KP to get the Kcpri and Kcpub;
    var kct = getBytesFromStorage("kct");
    var iv = getBytesFromStorage("iv");
    var aesCbc = new aesjs.ModeOfOperation.cbc(kct, iv);
    var decryptedBytes = aesCbc.decrypt(Kp);
    var keyPair = $.base64.encode(decryptedBytes).split(";");
    localStorage.setItem("Kcpub", keyPair[0]);
    localStorage.setItem("Kcpri", keyPair[1]);

    // validate timeStamp
    if (!validateTimeStamp(dataPackage.T)) return false;

    // parse token and nonce from eToken
    var encrypt = new JSEncrypt();
    encrypt.setPrivateKey('-----BEGIN PRIVATE KEY-----' + keyPair[1] + '-----END PRIVATE KEY-----');

    var nonceToken = encrypt.decrypt(eToken);
    var nonce = bytesToInt(HexString2Bytes(nonceToken).slice(0, 4));
    var token = nonceToken.slice(4);

    localStorage.setItem("nonce", nonce);
    localStorage.setItem("token", token);
    return true;
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
    var nonce = localStorage.getItem("nonce") + 1;
    localStorage.setItem("nonce", nonce);

    var token = getBytesFromStorage("token");

    var eTokenContent = intToBytes(nonce);
    for (var i = 0; i < token.length; i++) {
        eTokenContent.push(token[i]);
    }

    var encrypt = new JSEncrypt();
    var TPub = localStorage.getItem("TPub");
    encrypt.setPublicKey('-----BEGIN PUBLIC KEY-----' + TPub + '-----END PUBLIC KEY-----');
    var eToken = encrypt.encrypt(eTokenContent);

    return eToken;
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

    localStorage.setItem("timeStamp", timeStamp);
    return timeStampBase64;
}


/**
 * validate the timestamp with the last timeStamp
 * @param T the base64 encoded encrypted timeStamp
 * @returns {boolean} return true when the validate is successful
 */
function validateTimeStamp(T) {
    var key = localStorage.getItem("Kcpri");

    var encrypt = new JSEncrypt();
    encrypt.setPrivateKey('-----BEGIN PRIVATE KEY-----' + key + '-----END PRIVATE KEY-----');
    var de = encrypt.decrypt(T);
    var tim = HexString2Bytes(de);
    var timeStamp = bytesToInt(tim);
    var localTimeStamp = parseInt(localStorage.getItem("timeStamp")) + 1;
    localStorage.removeItem("timeStamp");
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
    return {data: data, T:timeStamp, EToken: eToken};
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


function encrypt() {
    var pub = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDlOJu6TyygqxfWT7eLtGDwajtN" +
    "FOb9I5XRb6khyfD1Yt3YiCgQWMNW649887VGJiGr/L5i2osbl8C9+WJTeucF+S76" +
    "xFxdU6jE0NQ+Z+zEdhUTooNRaY5nZiu5PgDB0ED/ZKBUSLKL7eibMxZtMlUDHjm4" +
    "gwQco1KRMDSmXSMkDwIDAQAB";
    var pri = "MIICXQIBAAKBgQDlOJu6TyygqxfWT7eLtGDwajtNFOb9I" +
        "5XRb6khyfD1Yt3YiCgQWMNW649887VGJiGr/L5i2osbl8C9+WJT" +
        "eucF+S76xFxdU6jE0NQ+Z+zEdhUTooNRaY5nZiu5PgDB0ED/ZKB" +
        "USLKL7eibMxZtMlUDHjm4gwQco1KRMDSmXSMkDwIDAQABAoGAfY" +
        "9LpnuWK5Bs50UVep5c93SJdUi82u7yMx4iHFMc/Z2hfenfYEzu+" +
        "57fI4fvxTQ//5DbzRR/XKb8ulNv6+CHyPF31xk7YOBfkGI8qjLo" +
        "q06V+FyBfDSwL8KbLyeHm7KUZnLNQbk8yGLzB3iYKkRHlmUanQG" +
        "aNMIJziWOkN+N9dECQQD0ONYRNZeuM8zd8XJTSdcIX4a3gy3GGC" +
        "JxOzv16XHxD03GW6UNLmfPwenKu+cdrQeaqEixrCejXdAFz/7+B" +
        "SMpAkEA8EaSOeP5Xr3ZrbiKzi6TGMwHMvC7HdJxaBJbVRfApFrE" +
        "0/mPwmP5rN7QwjrMY+0+AbXcm8mRQyQ1+IGEembsdwJBAN6az8R" +
        "v7QnD/YBvi52POIlRSSIMV7SwWvSK4WSMnGb1ZBbhgdg57DXasp" +
        "cwHsFV7hByQ5BvMtIduHcT14ECfcECQATeaTgjFnqE/lQ22Rk0e" +
        "GaYO80cc643BXVGafNfd9fcvwBMnk0iGX0XRsOozVt5AzilpsLB" +
        "YuApa66NcVHJpCECQQDTjI2AQhFc1yRnCU/YgDnSpJVm1nASoRU" +
        "nU8Jfm3Ozuku7JUXcVpt08DFSceCEX9unCuMcT72rAQlLpdZir876";

    localStorage.setItem("SPub", pub);
    localStorage.setItem("Kcpri", pri);
    var timeStamp = generateTimeStamp();
    console.log(timeStamp);
    console.log(validateTimeStamp(timeStamp));
}


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