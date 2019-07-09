/**
 * get the SPub and TPub from server, store it in localStorage
 * @param serverUrl the url of the server.
 */
function initialize(serverUrl) {
    // localStorage.removeItem("SPub");
    // localStorage.removeItem("TPub");
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
                    validateQRInitialResponsePackage(data);
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
 * used to parse the response package from the server during the login process
 * @param dataPackage {json} the payload of the response package
 * @returns {boolean} return true when there is no fault
 */
function validateQRInitialResponsePackage(dataPackage) {
    var eToken = $.base64.decode(dataPackage.EToken);
    var Kp = $.base64.decode(dataPackage.Kp);

    //decrypt KP to get the Kcpri and Kcpub;
    var kct = HexString2Bytes(sessionStorage.getItem("kct"));
    var iv = HexString2Bytes(sessionStorage.getItem("iv"));
    sessionStorage.removeItem("kct");
    sessionStorage.removeItem("iv");
    var aesCbc = new aesjs.ModeOfOperation.cbc(kct, iv);
    var keyPair = aesCbc.decrypt(HexString2Bytes(b64tohex(Kp)));
    var split = findSplit(keyPair);
    var Kcpub = hex2b64(Bytes2HexString(keyPair.slice(0, split)));
    var Kcpri = hex2b64(Bytes2HexString(keyPair.slice(split+1, keyPair.length)));

    localStorage.setItem("Kcpub", Kcpub);
    localStorage.setItem("Kcpri", Kcpri);

    // parse token and nonce from eToken
    var encrypt = new JSEncrypt();
    encrypt.setPrivateKey('-----BEGIN RSA PRIVATE KEY-----' + keyPair[1] + '-----END RSA PRIVATE KEY-----');

    var nonceToken = encrypt.decrypt(eToken);
    var nonce = bytesToInt(HexString2Bytes(nonceToken.substr(0, 8)));
    var token = nonceToken.substr(8);

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
    QRCodeElement.clear("click");
    QRCodeElement.click(click_function ? click_function : function () {
        QRAuthentation(QRCodeUrl, pollingUrl, targetUrl, QRCodeElement, click_function);
    });

    generateKctAndIv();
    var data = {kct: sessionStorage.getItem("kct"), iv: sessionStorage.getItem("iv")};
    $.ajax({
        url: QRCodeUrl,
        type: "post",
        data: JSON.stringify(data),
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


function generateKctAndIv() {
    var RandomSeed = randomPassword(10); // used to generate Kct and iv
    var kct = $.md5(RandomSeed);
    var iv = sha256(RandomSeed).substr(0, 16);

    sessionStorage.setItem("kct", kct);
    sessionStorage.setItem("iv", iv);
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
    var eToken = $.base64.decode(dataPackage.EToken);
    var Kp = $.base64.decode(dataPackage.Kp);

    //decrypt KP to get the Kcpri and Kcpub;
    var kct = HexString2Bytes(sessionStorage.getItem("kct"));
    var iv = HexString2Bytes(sessionStorage.getItem("iv"));
    sessionStorage.removeItem("kct");
    sessionStorage.removeItem("iv");
    var aesCbc = new aesjs.ModeOfOperation.cbc(kct, iv);
    var keyPair = aesCbc.decrypt(HexString2Bytes(b64tohex(Kp)));
    var split = findSplit(keyPair);
    var Kcpub = hex2b64(Bytes2HexString(keyPair.slice(0, split)));
    var Kcpri = hex2b64(Bytes2HexString(keyPair.slice(split+1, keyPair.length)));

    localStorage.setItem("Kcpub", Kcpub);
    localStorage.setItem("Kcpri", Kcpri);

    // validate timeStamp
    if (!validateTimeStamp(dataPackage.T)) return false;

    // parse token and nonce from eToken
    var encrypt = new JSEncrypt();
    encrypt.setPrivateKey('-----BEGIN RSA PRIVATE KEY-----' + keyPair[1] + '-----END RSA PRIVATE KEY-----');

    var nonceToken = encrypt.decrypt(eToken);
    var nonce = bytesToInt(HexString2Bytes(nonceToken.substr(0, 8)));
    var token = nonceToken.substr(8);

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
    var key = localStorage.getItem("Kcpri");

    var encrypt = new JSEncrypt();
    encrypt.setPrivateKey('-----BEGIN PRIVATE KEY-----' + key + '-----END PRIVATE KEY-----');

    var timeStamp = bytesToInt(HexString2Bytes(encrypt.decrypt(T)));
    var localTimeStamp = parseInt(localStorage.getItem("timeStamp")) + 1;
    sessionStorage.removeItem("timeStamp");
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

    localStorage.setItem("TPub", pub);
    localStorage.setItem("Kcpri", pri);

    var pubKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwibfwzLDKKbGFBn1UtwQJDSw1unxEJbdci3EpMlKgS0ki5p5l0hJxoOgrZfEcNdEga1hgDPoF9Yk9FJvHhNX/+FiXRME3B98d2DjAzOYNXizMNPw9baSyaPl7vdF815b8yMIX1l2AYJcsljj/G6liqRSy0FZpOV3RiPMTOQGxPgsBfrfTq7CiudDN2X16sOoSI233jW9ulKwjcdH0lXMUTD1dIwy30KJC9vmnmmeKa7LzDThLL3ep22CDqdIMX3MHpgpi+c+Gd0hZq+nz8U7je+9JGA9HFu7n6Y85QXNUsgzVoi3TDIqvoIBPU5+8ogg3uG8ndSI7rmgmaUHXjGvtwIDAQAB";
    var priKey = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCiVAt4YLKMoBjW+TD+EqMQsptKXjg/hQ3feqPgXVK552EWxbJ7yo/ZnxWuhfGa7iBmj+61bC0GUNCThBnQZF9ovU/EfKc6XtfQSfpfXj+Zzwl/iYfATh57St8edbcmK7QumzWkFgYNWY4AICZEgAFdxWwlQYuvLWoOi8T2yrCu47AqPcPumYoDJVaqbafGdcQPUYeQzECucHTU6R2SVg7gSMfxj/A2eKXPFrl9/tYAR/mzW0TE64+nuOo4dy2DPhI2c5UJOhtJWP57zcLvc7yBuDAiutLI+ZC2Jf8roM9g0C+hq+dkYCwr+MiEw4z1+4RUExY/msjIUXYCBU1AVwVpAgMBAAECggEAfXjbONv9hydEq/4HuYvsUT7NO+miLq8I7yHbw9Q+2oWXjUOY14jWMg9+cd0EyI2hq8U7bS5FiykyX6PvVB4RhWM3Yhg8JqkixdQ43Dh8jsXygItsy99WPlS8K84vmCiV6KR+DOwdF3qOgVhYXABZjgLIue91Kh2/aajtwRkhAryueicByg2F5gQovEO+MHx647glYOIGVQYxM2V7cVpYkYyK4w7N+lzcpi3F7+1KHpkkFZ28FW7cBROKVqaHvhOoLExXin8Bxr5wxd+jG73RRlOlxTwW4QCfolgKae4l39o80oTKPo8VpNq5620m9xBtB03IzO2I5cFyAWlYRt071QKBgQDVUTGfqknUvkOGzEXT0xEhqoQlKpe/sLJYzDoQyD4ffdIchCOzVx4b6Qw8Oi0MGc+k6AWBlUajk8jfny6GGavn8TmAqRabby1VIgaSk8mb40Uc3Gd2V0knJ/ApEefv3LA0smlaS9yOY6VRTntAKi+pYgZuyceRZs1Rth/q3ql2jwKBgQDCzwinrNk04Tb7QskQz19sFO4V8C0jwx+RJJn446Kr/tYeqA+tCo7DMOXTLCmW8LzVlh3TYc0r+dKpqi8Gcn5b20VE4XpF+YMJHBTrGLwwWuiZ6cejgylyocY/xXSmirgj/HeLWwXYsplIQNV+1zsJ+Hfr1jxh7kRm6Jx/dC6AhwKBgQCR0RnJ2f70JUdFmtdUsCAy0jvYqB/pUiDn4FsE48zLfBenlJBO5ItZatoJRX9LmU0+nbg910vdP4V9j3OfCWdgep3jHDKu97WWT1cM1WdoX1f8HZG/7HS+Bmf9uxa/+SyeKSMpLVhMIUN9q9dGik/gSni5PMdl1k8dvxBcXe6bcwKBgCXpSJPpDXQ/CAYp3xtIYBeWkybt0LsO9Au5BcXr9vJl66GXr0VLsrDFyVQpWgan3vfp+O/0LouKWLbwCarFiVWy/G4FO1h20EtrjZ6a97SpXG7nkhR+KAjI9t3ePW9Tu7Y1Icaa9i5Pw4jOJT5EAJdWJXBeBu5AAkvMpPgg0hPtAoGBAIxRnGtdqQue6HdXuXH2ogpS83YhU0LuhHJ7q5Ex1WtWiIAtWKnl8OC9soVN7nHvM+Om5fIqRcb4+JNuu5bzdtU4Pgdv6dfYicOZJUEvIm+1CzqeH3hPp70vGVHGu0h7ayrQOqyRYuWED/wxKNHlBzkHrAhDuAVCF0zoSj2RERb7";
    var en = "P8rw+Bkzp6tvhWa8lqGORvdSpIDIA+ulIV5BCYajfStOOqPfNpfjGSmnQwaKSnsrMHXZtes0tdjSUeJYMIbwdn7q02wqqrPkttCQp1mttpJHudm5LcPQVwFZEGA7izLSQZkHluAkiRxUcLX3He9pKHNFuz1uVhnRmELcDs4OqsGHnA3LaTQhL+aDNtiVwIxCl9JWHqDvXHkXhemA/3+bDjG6uwi9BeFrLuyChI9qUBFkOEZfr2u6jSCwM3lhHu9/egU3W697lexwJqrk/sv3F5HKcgHqc+ZJyAt9LGBjCA3iZHk9I8TU5pN4q1EptW4ucdmSQ7LDTP77yiV/hmvwYA==";
    var encrypt = new JSEncrypt();
    encrypt.setPublicKey('-----BEGIN PUBLIC KEY-----' + pubKey + '-----END PUBLIC KEY-----');
    encrypt.setPrivateKey('-----BEGIN RSA PRIVATE KEY-----' + priKey + '-----END RSA PRIVATE KEY-----');
    var de = encrypt.decrypt(en);
    console.log(de);

    var str = de.substr(0, 8);
    var bytes = HexString2Bytes(str);
    console.log(bytesToInt(bytes));
}
