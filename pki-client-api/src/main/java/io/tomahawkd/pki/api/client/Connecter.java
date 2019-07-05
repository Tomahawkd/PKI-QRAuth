

package io.tomahawkd.pki.api.client;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import io.tomahawkd.pki.api.client.util.SecurityFunctions;
import io.tomahawkd.pki.api.client.util.Utils;
import io.tomahawkd.pki.api.client.util.httpUtil;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

public class Connecter {
    public Connecter() {
    }

    public String getAuthenticationServerPublicKey() {
        String uri = "39.106.80.38:22222/keys/auth/pubkey";
        String res = httpUtil.getJsonData(uri);
        return res;
    }

    public String getServerPublicKey(String id) {
        String uri = "192.168.43.192:8000/serverkey";
        String a = httpUtil.getJsonData(id, uri);
        return a;
    }

    public String initalizeAuthentication(String user, String pass, PublicKey Tpub, PublicKey Spub) throws Exception {
        Gson gson = new Gson();
        Map<String, Object> map1 = new HashMap();
        map1.put("username", user);
        map1.put("password", pass);
        String json1 = gson.toJson(map1);
        int t = SecurityFunctions.generateRandom();
        byte[] Kcs = SecurityFunctions.generateRandom(32);
        byte[] Kct = SecurityFunctions.generateRandom(32);
        byte[] iv = SecurityFunctions.generateRandom(16);
        String payload = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(Spub, json1.getBytes()));
        String S = new String(SecurityFunctions.encryptAsymmetric(Spub, ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(t).array()), "UTF-8");
        String K = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(Tpub, Kct));
        String IV = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(Tpub, iv));
        Map<String, Object> map = new HashMap();
        map.put("payload", payload);
        map.put("S", S);
        map.put("K", K);
        map.put("iv", IV);
        String json = gson.toJson(map);
        String uri = "192.168.43.159...";
        String res = httpUtil.getJsonData(json, uri);
        Map<String, String> result = (Map)(new Gson()).fromJson(res, (new TypeToken<Map<String, String>>() {
        }).getType());
        String m = new String((String)result.get("M"));
        Map<String, Object> message = (Map)(new Gson()).fromJson(m, (new TypeToken<Map<String, Integer>>() {
        }).getType());
        if ((Integer)message.get("status") == 0) {
            String[] kp = (new String(SecurityFunctions.decryptSymmetric(Kct, iv, Utils.base64Decode((String)result.get("KP"))))).split(";");
            KeyPair keyPair = SecurityFunctions.readKeysFromString(kp[1], kp[0]);
            byte[] etoken = SecurityFunctions.decryptAsymmetric(keyPair.getPrivate(), Utils.base64Decode((String)result.get("EToken")));
            int nonce = ByteBuffer.wrap(etoken).order(ByteOrder.LITTLE_ENDIAN).getInt();
            byte[] token = new byte[etoken.length - 4];
            System.arraycopy(etoken, 4, token, 0, etoken.length - 4);
            String T = new String(SecurityFunctions.decryptAsymmetric(keyPair.getPrivate(), (new String(Utils.base64Decode((String)result.get("T")), "UTF-8")).getBytes()));
            int t1 = ByteBuffer.wrap(T.getBytes()).order(ByteOrder.LITTLE_ENDIAN).getInt();
            int check = 0;
            if (t1 != t + 1) {
                check = 1;
            }

            Map<String, Object> re = new HashMap();
            re.put("nonce", nonce);
            re.put("Token", token);
            re.put("Cpri", keyPair.getPrivate());
            re.put("Cpub", keyPair.getPublic());
            re.put("check", Integer.valueOf(check));
            re.put("message", "success");
            return gson.toJson(re);
        } else {
            Map<String, String> map3 = new HashMap();
            map3.put("message", (String)message.get("message"));
            return gson.toJson(map3);
        }
    }

    public String interactAuthentication(String data, PublicKey Tpub, PublicKey Spub, byte[] token, int nonce, PrivateKey Cpri) throws Exception {
        Gson gson = new Gson();
        String payload = Utils.base64Encode(data.getBytes());
        byte[] tokenArr = ByteBuffer.allocate(token.length + 4).order(ByteOrder.LITTLE_ENDIAN).putInt(nonce).put(token).array();
        String etokenReq = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(Tpub, tokenArr));
        int tReq = SecurityFunctions.generateRandom();
        String tStringReq = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(Spub, ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(tReq).array()));
        Map<String, String> reqMap = new HashMap();
        reqMap.put("payload", payload);
        reqMap.put("EToken", etokenReq);
        reqMap.put("T", tStringReq);
        String json = (new Gson()).toJson(reqMap);
        String uri = "39.106.80.38:22222/keys/auth/pubkey";
        String res = httpUtil.getJsonData(json, uri);
        Map<String, String> result = (Map)(new Gson()).fromJson(res, (new TypeToken<Map<String, String>>() {
        }).getType());
        String m = new String(Utils.base64Decode((String)result.get("M")), "UTF-8");
        Map<String, Object> message = (Map)(new Gson()).fromJson(m, (new TypeToken<Map<String, Integer>>() {
        }).getType());
        if ((Integer)message.get("status") == 0) {
            String T = new String(SecurityFunctions.decryptAsymmetric(Cpri, (new String(Utils.base64Decode((String)result.get("T")), "UTF-8")).getBytes()));
            int t1 = ByteBuffer.wrap(T.getBytes()).order(ByteOrder.LITTLE_ENDIAN).getInt();
            int check = 0;
            String data1;
            HashMap map3;
            if (t1 != tReq + 1) {
                check = 1;
                data1 = Utils.base64Decode((String)result.get("payload")).toString();
                map3 = new HashMap();
                map3.put("check", Integer.valueOf(check));
                return gson.toJson(map3);
            } else {
                data1 = Utils.base64Decode((String)result.get("payload")).toString();
                map3 = new HashMap();
                map3.put("check", Integer.valueOf(check));
                map3.put("data", data1);
                return gson.toJson(map3);
            }
        } else {
            Map<String, Object> map4 = new HashMap();
            map4.put("check", 1);
            return gson.toJson(map4);
        }
    }

    public String updateQRStatus(byte[] token, int nonce, String nonce2, PublicKey Tpub, PublicKey Spub, PrivateKey Cpri) throws Exception {
        Gson gson = new Gson();
        byte[] tokenArr = ByteBuffer.allocate(token.length + 4).order(ByteOrder.LITTLE_ENDIAN).putInt(nonce + 1).put(token).array();
        String etokenReq = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(Tpub, tokenArr));
        String EToken = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(Tpub, etokenReq.getBytes()));
        int t = SecurityFunctions.generateRandom();
        String T = new String(SecurityFunctions.encryptAsymmetric(Spub, ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(t).array()), "UTF-8");
        String N = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(Tpub, nonce2.getBytes()));
        Map<String, Object> map = new HashMap();
        map.put("EToken", EToken);
        map.put("T", T);
        map.put("N", N);
        String json = gson.toJson(map);
        String uri = "39.106.80.38:22222/keys/auth/pubkey";
        String res = httpUtil.getJsonData(json, uri);
        Map<String, String> result = (Map)(new Gson()).fromJson(res, (new TypeToken<Map<String, String>>() {
        }).getType());
        String m = (String)result.get("M");
        Map<String, String> m1 = (Map)(new Gson()).fromJson(m, (new TypeToken<Map<String, String>>() {
        }).getType());
        int t1;
        boolean check;
        HashMap map2;
        byte check;
        if (((String)m1.get("type")).equals("1")) {
            new String(SecurityFunctions.decryptAsymmetric(Cpri, (new String(Utils.base64Decode((String)result.get("T")), "UTF-8")).getBytes()));
            t1 = ByteBuffer.wrap(T.getBytes()).order(ByteOrder.LITTLE_ENDIAN).getInt();
            check = false;
            if (t1 == t + 1) {
                check = 1;
                map2 = new HashMap();
                map2.put("check", Integer.valueOf(check));
                map2.put("message", "Success");
                return gson.toJson(map2);
            }
        } else {
            new String(SecurityFunctions.decryptAsymmetric(Cpri, (new String(Utils.base64Decode((String)result.get("T")), "UTF-8")).getBytes()));
            t1 = ByteBuffer.wrap(T.getBytes()).order(ByteOrder.LITTLE_ENDIAN).getInt();
            check = false;
            if (t1 != t + 1) {
                check = 1;
                map2 = new HashMap();
                map2.put("check", Integer.valueOf(check));
                map2.put("message", "QRcode Invalid");
                return gson.toJson(map2);
            }

            if (t1 == t + 1) {
                check = 2;
                map2 = new HashMap();
                map2.put("check", Integer.valueOf(check));
                map2.put("message", "QRcode Invalid");
                return gson.toJson(map2);
            }
        }

        return res;
    }

    public String updateQRStatusConfirm(byte[] token, int nonce, String nounce2, PublicKey Tpub, PublicKey Spub, PrivateKey Cpri, int confirm) throws Exception {
        Gson gson = new Gson();
        byte[] tokenArr = ByteBuffer.allocate(token.length + 4).order(ByteOrder.LITTLE_ENDIAN).putInt(nonce + 1).put(token).array();
        String etokenReq = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(Tpub, tokenArr));
        String EToken = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(Tpub, etokenReq.getBytes()));
        int t = SecurityFunctions.generateRandom();
        String T = new String(SecurityFunctions.encryptAsymmetric(Spub, ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(t).array()), "UTF-8");
        Map<String, Object> map2 = new HashMap();
        map2.put("status", 2);
        map2.put("message", confirm);
        String M = gson.toJson(map2);
        Map<String, Object> map = new HashMap();
        map.put("M", M);
        map.put("EToken", EToken);
        map.put("T", T);
        String json = gson.toJson(map);
        String uri = "39.106.80.38:22222/keys/auth/pubkey";
        String res = httpUtil.getJsonData(json, uri);
        Map<String, String> result = (Map)(new Gson()).fromJson(res, (new TypeToken<Map<String, String>>() {
        }).getType());
        new String(SecurityFunctions.decryptAsymmetric(Cpri, (new String(Utils.base64Decode((String)result.get("T")), "UTF-8")).getBytes()));
        int t1 = ByteBuffer.wrap(T.getBytes()).order(ByteOrder.LITTLE_ENDIAN).getInt();
        String M2 = new String(SecurityFunctions.decryptAsymmetric(Cpri, (new String(Utils.base64Decode((String)result.get("M")), "UTF-8")).getBytes()));
        Map<String, Object> M3 = (Map)(new Gson()).fromJson(M2, (new TypeToken<Map<String, String>>() {
        }).getType());
        if ((Integer)M3.get("status") == 1) {
            Map<String, Object> map4 = new HashMap();
            map2.put("check", 2);
            map2.put("message", "Invalid!");
            return gson.toJson(map4);
        } else {
            int check = false;
            byte check;
            if (t1 != t + 1) {
                check = 1;
                new HashMap();
                map2.put("check", Integer.valueOf(check));
                map2.put("message", "Timestamp incorrect!");
                return gson.toJson(map2);
            } else if (t1 == t + 1) {
                check = 0;
                new HashMap();
                map2.put("check", Integer.valueOf(check));
                map2.put("message", "Success");
                return gson.toJson(map2);
            } else {
                return res;
            }
        }
    }
}