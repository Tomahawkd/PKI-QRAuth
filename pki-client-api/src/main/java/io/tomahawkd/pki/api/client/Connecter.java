package io.tomahawkd.pki.api.client;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.reflect.TypeToken;
import com.sun.scenario.effect.impl.sw.sse.SSEBlend_ADDPeer;
import io.tomahawkd.pki.api.client.exceptions.*;
import io.tomahawkd.pki.api.client.util.*;
import io.tomahawkd.pki.api.client.util.Utils;
import sun.rmi.runtime.Log;

import javax.jws.Oneway;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Connecter{

    /**
     * param {null}
     * return Tpub
     *
     */
    public String getAuthenticationServerPublicKey(String url,String ua){
        return httpUtil.getJsonData(url,ua);
    }

    public String getServerPublicKey(String url,String ua){
        return  httpUtil.getJsonData(url,ua);
    }

    /**
     * @param  {
     *     "payload" : "Base64 encoded Ks public key encrypted data message",
     *     "T" : "Base64 encoded Ks public key encrypted Timestamp and Kcs",
     *     "K" : "Base64 encoded Kc,t encrypted Kt public",
     *     "iv" : "Base64 encoded Kt public key encrtpted Initial vector"
     * }
     * @return
     * {"nonce": "nonce int",
     *  "Token": "token message",
     *  "Cpri": "Private key of Client"
     *  "Cpub" : "Public key of Client"
     *  "check" : "0:success/1:timestamp error/2:Authentication failed"
     *  "message" : "succuess/timestamp error/Authentication failed"
     *  }
     */

    public String initalizeAuthentication(String url,String user_json, PublicKey Tpub,PublicKey Spub,String ua) throws Exception {

        //generate the symmetric ky between C and T
        byte[] Kct = SecurityFunctions.generateRandom(32);
        //generte the initial vector
        byte[] iv = SecurityFunctions.generateRandom(16);
        int t = SecurityFunctions.generateRandom();
        String T1 = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(Spub,
                ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(t).array()));

        String K = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(Tpub, Kct));
        String IV = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(Tpub, iv));

        Map<String, String> map = new HashMap<>();
        map.put("payload", user_json);
        map.put("T", T1);
        map.put("K", K);
        map.put("iv", IV);
        Gson gson = new Gson();
        String json = gson.toJson(map);
        String res = httpUtil.getJsonData(json,url,ua);

        Map<String, String> result =
                new Gson().fromJson(res, new TypeToken<Map<String, String>>() {
                }.getType());
        String m = result.get("M");
        Message<String> message = new Gson().fromJson(m, new TypeToken<Message<String>>() {
        }.getType());

        String[] kp =
                new String(SecurityFunctions.decryptSymmetric(Kct, iv, Utils.base64Decode(result.get("KP"))))
                        .split(";");
        KeyPair keyPair = SecurityFunctions.readKeysFromString(kp[1], kp[0]);
        // 收到的T
        byte[] T = SecurityFunctions.decryptAsymmetric(keyPair.getPrivate(), Utils.base64Decode(result.get("T")));
        // 转化
        int t1 = ByteBuffer.wrap(T).order(ByteOrder.LITTLE_ENDIAN).getInt();
        System.out.println("t1" + t1);
        System.out.println("t" + t);

        if (t1 == t + 1) {
            if (message.isOk()) {

                byte[] etoken = SecurityFunctions.decryptAsymmetric(keyPair.getPrivate(),
                        Utils.base64Decode(result.get("EToken")));
                int nonce = ByteBuffer.wrap(etoken).order(ByteOrder.LITTLE_ENDIAN).getInt();
                byte[] token = new byte[etoken.length - Integer.BYTES];
                System.arraycopy(etoken, Integer.BYTES, token, 0, etoken.length - Integer.BYTES);
                Map<String, Object> re = new HashMap<>();
                re.put("nonce", nonce);
                re.put("Token", Utils.base64Encode(token));
                re.put("Cpri", kp[1]);
                re.put("Cpub", kp[0]);
                re.put("check", 0);
                re.put("message",message.getMessage());
                return gson.toJson(re);
            } else {
                Map<String, Object> map3 = new HashMap<>();
                map3.put("check", 2);
                map3.put("message", message.getMessage());
                return gson.toJson(map3);
            }
        } else {
            Map<String, Object> re = new HashMap<>();
            re.put("check", 1);
            re.put("message", message.getMessage());
            return gson.toJson(re);
        }

    }


    /**
     * @param  {
     *     "payload" : "Base64 encoded Ks public key encrypted data message",
     *     "EToken" : "Base64 encoded Kt public key encrypted token,nonce+1",
     *     "T" : "Base64 encoded Ks public key encrypted challenge number",
     * }
     * @return
     * {
     *   "data" : "Base64 encoded Kc public key encrypted payload",
     *   "check" : "0:success/1:timestamp error/2:Authentication failed",
     *   "message" : ""0:success/1:timestamp error/2:Authentication failed""
     *  }
     */

    public String interactAuthentication(String url,String user_json,PublicKey Tpub,PublicKey Spub,byte[] token,int nonce,PrivateKey Cpri,String ua) throws Exception{
        Gson gson = new Gson();
        String EToken = Utils.generateEtoken(token,nonce,Tpub);
        int t = SecurityFunctions.generateRandom();
        String tStringReq = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(Spub,
                ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(t).array()));

        Map<String, String> reqMap = new HashMap<>();
        reqMap.put("payload",user_json);
        reqMap.put("EToken", EToken);
        reqMap.put("T", tStringReq);
        String json = new Gson().toJson(reqMap);

        String res = httpUtil.getJsonData(json,url,ua);

        Map<String,String> result = new Gson().fromJson(res, new TypeToken<Map<String,String>>() {}.getType());
        String m = result.get("M");
        Message<String> message = new Gson().fromJson(m,new TypeToken<Message<String>>(){}.getType());

        if(message.getStatus()!=0){
            Map<String, Object> map3 = new HashMap<>();
            map3.put("check", "5");
            map3.put("message", "Token同步失败！请重新登录");
            return gson.toJson(map3);
        }

        byte[] T = SecurityFunctions.decryptAsymmetric(Cpri,Utils.base64Decode(result.get("T")));
        int t1 = ByteBuffer.wrap(T).order(ByteOrder.LITTLE_ENDIAN).getInt();
        if(t1 == t+1){
            if (message.isOk()) {
                String data1 = result.get("payload");
                Map<String, String> map3 = new HashMap<>();
                map3.put("data",data1);
                map3.put("check", "0");
                map3.put("message",message.getMessage());
                return gson.toJson(map3);
            }else {
                Map<String, String> map3 = new HashMap<>();
                map3.put("check", "2");
                map3.put("message", message.getMessage());
                return gson.toJson(map3);
            }
        }
        else {
            Map<String, String> map4 = new HashMap<>();
            map4.put("check","1");
            map4.put("mssage", message.getMessage());
            return gson.toJson(map4);
        }
    }

    /**
     * @param  { "M": {
     *             "status": "1",
     *             "message":"Base64 encoded Kt public key encrypted nonce2"
     *             }
     *             "EToken": "Base64 encoded Kt public key encrypted token,nonce",
     *             "T": "Base64 encoded Kt public key encrypted challenge number",
     *             }
     * @return {
     *          {
     *             "check" : "0:success/1:timestamp error/2:Authentication failed"
     *             "message" : "succuess/timestamp error/Authentication failed"
     *          }
     */
    public String updateQRStatus(String url,byte[] token, int nonce, String nonce2, PublicKey Tpub, PublicKey Spub, PrivateKey Cpri,String ua) throws Exception{
        Gson gson = new Gson();
        // generate the EToken
        String EToken = Utils.generateEtoken(token,nonce,Tpub);
        //generate T
        int t = SecurityFunctions.generateRandom();
        String T = Utils.base64Encode((SecurityFunctions.encryptAsymmetric(Spub,
                ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(t).array())));
        //generate message

        String QRString = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(Tpub,
                ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(Integer.parseInt(nonce2)).array()));

        Map<String,Object> M = new HashMap<>();
        M.put("status",1);
        M.put("message",QRString);
        String M1 = gson.toJson(M);

        Map<String,String> map = new HashMap<>();
        map.put("EToken",EToken);
        map.put("T",T);
        map.put("M",M1);
        String json = gson.toJson(map);

        String res = httpUtil.getJsonData(json,url,ua);

        Map<String,String> result = new Gson().fromJson(res,new TypeToken<Map<String,String>>(){}.getType());

        String m = result.get("M");
        Message<String> message = new Gson().fromJson(m,new TypeToken<Message<String>>(){}.getType());

        byte[] T1 = SecurityFunctions.decryptAsymmetric(Cpri,Utils.base64Decode(result.get("T")));
        int t1 = ByteBuffer.wrap(T1).order(ByteOrder.LITTLE_ENDIAN).getInt();

        if(t1 == t+1){
            if(message.isOk()){
                Map<String,Object> map2 = new HashMap<>();
                map2.put("check",0);
                map2.put("message",message.getMessage());
                return gson.toJson(map2);
            } else {
                Map<String,Object> map3 = new HashMap<>();
                map3.put("check",2);
                map3.put("message",message.getMessage());
                return gson.toJson(map3);
            }
        } else {
            Map<String,Object> map3 = new HashMap<>();
            map3.put("check",1);
            map3.put("message",message.getMessage());
            return gson.toJson(map3);
        }
    }

    /**
     * @param  { "M": {
     *             "status": 2:",
     *             "message":"1:true/0:false"
     *             }
     *             "EToken": "Base64 encoded Kt public key encrypted token,nonce",
     *             "T": "Base64 encoded Kt public key encrypted challenge number",
     *             }
     * @return {
     *          {
     *            "check": "0:success/1:timestamp error/2:Authentication failed"
     *            "message" : "succuess/timestamp error/Authentication failed"
     *          }
     */

    public String updateQRStatusConfirm(String url,byte[] token, int nonce, PublicKey Tpub, PublicKey Spub, PrivateKey Cpri,String confirm,String ua) throws Exception{
        Gson gson = new Gson();
        // generate the EToken
        String EToken = Utils.generateEtoken(token,nonce,Tpub);
        // generate T
        int t = SecurityFunctions.generateRandom();
        String T = Utils.base64Encode((SecurityFunctions.encryptAsymmetric(Spub,
                ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(t).array())));

        Map<String,Object> map2 = new HashMap<>();
        map2.put("status",2);
        map2.put("message",confirm);
        String M = gson.toJson(map2);
        Map<String,String> map = new HashMap<>();
        map.put("M",M);
        map.put("EToken",EToken);
        map.put("T",T);
        String json = gson.toJson(map);
        String res = httpUtil.getJsonData(json,url,ua);
        Map<String,String> result = new Gson().fromJson(res,new TypeToken<Map<String,String>>(){}.getType());

        byte[] T1 = SecurityFunctions.decryptAsymmetric(Cpri,Utils.base64Decode(result.get("T")));
        int t1 = ByteBuffer.wrap(T1).order(ByteOrder.LITTLE_ENDIAN).getInt();

        String M2 = result.get("M");
        Message<String> message = new Gson().fromJson(M2,new TypeToken<Message<String>>(){}.getType());        //assertThat(result.get("M")).contains("\"status\":0");
        if(t1 == t+1){
            if(message.isOk()){
                Map<String,Object> map3 = new HashMap<>();
                map3.put("check",0);
                map3.put("message",message.getMessage());
                return gson.toJson(map3);
            } else {
                Map<String,Object> map3 = new HashMap<>();
                map3.put("check",2);
                map3.put("message",message.getMessage());
                return gson.toJson(map3);
            }
        } else {
            Map<String,Object> map3 = new HashMap<>();
            map3.put("check",1);
            map3.put("message",message.getMessage());
            return gson.toJson(map3);
        }
    }

    /**
     * @param {
     *             "EToken": "Base64 encoded Kt public key encrypted token,nonce+1(by client)",
     *             "T": "Base64 encoded Kt public key encrypted challenge number",
     *             }
     * @return {
     *          "check": "0:success/1:timestamp error/2:Authentication failed"
     *          "message" : "succuess/timestamp error/Authentication failed"
     *          "logList" : "list of logs"
     */

    public String getLog(String url,byte[] token,int nonce,PublicKey Tpub,PublicKey Spub,String ua,PrivateKey Cpri) throws CipherErrorException, UnsupportedEncodingException {
        Gson gson = new Gson();
        // generate the EToken
        String EToken = Utils.generateEtoken(token,nonce,Tpub);
        // generate T
        int t = SecurityFunctions.generateRandom();
        String T = Utils.base64Encode((SecurityFunctions.encryptAsymmetric(Spub,
                ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(t).array())));

        Map<String,Object> map = new HashMap<>();
        map.put("EToken",EToken);
        map.put("T",T);
        String json = gson.toJson(map);
        String res = httpUtil.getJsonData(json,url,ua);
        Map<String,String> result = new Gson().fromJson(res,new TypeToken<Map<String,String>>(){}.getType());

        byte[] T1 = SecurityFunctions.decryptAsymmetric(Cpri,Utils.base64Decode(result.get("T")));
        int t1 = ByteBuffer.wrap(T1).order(ByteOrder.LITTLE_ENDIAN).getInt();

        String M2 = result.get("M");
        Message<List<Map<String,String>>> message = new Gson().fromJson(M2,new TypeToken<Message<List<Map<String,String>>>>(){}.getType());
        if(t1 == t+1){
            if(message.isOk()){
                List<Map<String,String>> logList = new ArrayList<>();
                logList = message.getMessage();
                Map<String,Object> map3 = new HashMap<>();
                map3.put("check",0);
                map3.put("message","Success");
                map3.put("logList",logList);


                return gson.toJson(map3);
            } else {
                Map<String,Object> map3 = new HashMap<>();
                map3.put("check",2);
                map3.put("message","日志获取失败，请重试！");
                return gson.toJson(map3);
            }
        } else {
            Map<String,Object> map3 = new HashMap<>();
            map3.put("check",1);
            map3.put("message","time check error!");
            return gson.toJson(map3);
        }
    }
    /**
     * @param {
     *             "EToken": "Base64 encoded Kt public key encrypted token,nonce+1(by client)",
     *             "T": "Base64 encoded Kt public key encrypted challenge number",
     *             }
     * @return {
     *
     * "check": "0:success/1:timestamp error/2:Authentication failed"
     * "message" : "succuess/timestamp error/Authentication failed"
     * "tokenList" : "list of token messages"
     */

    public String initTokenList(String url,byte[] token,int nonce,PublicKey Tpub,PublicKey Spub,String ua,PrivateKey Cpri) throws CipherErrorException, UnsupportedEncodingException {
        Gson gson = new Gson();
        // generate the EToken
        String EToken = Utils.generateEtoken(token,nonce,Tpub);

        // generate T
        int t = SecurityFunctions.generateRandom();
        String T = Utils.base64Encode((SecurityFunctions.encryptAsymmetric(Spub,
                ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(t).array())));
        Map<String,Object> map = new HashMap<>();
        map.put("EToken",EToken);
        map.put("T",T);
        String json = gson.toJson(map);
        String res = httpUtil.getJsonData(json,url,ua);

        Map<String,String> result = new Gson().fromJson(res,new TypeToken<Map<String,String>>(){}.getType());
        byte[] T1 = SecurityFunctions.decryptAsymmetric(Cpri,Utils.base64Decode(result.get("T")));
        int t1 = ByteBuffer.wrap(T1).order(ByteOrder.LITTLE_ENDIAN).getInt();
        String M2 = result.get("M");

        Message<List<Map<String, String>>> message = new Gson().fromJson(M2,new TypeToken<Message<List<Map<String, String>>>>(){}.getType());
        if(t1 == t+1){
            if(message.isOk()){
                List<Map<String,String>> tokenList = new ArrayList<>();
                tokenList = message.getMessage();
                Map<String,Object> map3 = new HashMap<>();
                map3.put("check",0);
                map3.put("message",message.getMessage());
                map3.put("tokenList",tokenList);
                return gson.toJson(map3);
            } else {
                Map<String,Object> map3 = new HashMap<>();
                map3.put("check",2);
                map3.put("message","Get token list failed!");
                return gson.toJson(map3);
            }
        } else {
            Map<String,Object> map3 = new HashMap<>();
            map3.put("check",1);
            map3.put("message","time stamp fail!");
            return gson.toJson(map3);
        }

    }

    /**
     * @param {
     *             "M": {
     *             "status": "0",
     *             "message":"Tokenid"
     *             }
     *             "EToken": "Base64 encoded Kt public key encrypted token,nonce+1(by client)",
     *             "T": "Base64 encoded Kt public key encrypted challenge number",
     *             }
     * @return {
     * "check": "0:success/1:timestamp error/2:Authentication failed"
     * "message" : "succuess/timestamp error/Authentication failed"
     * }
     */

    public String revokeToken(String tokenid,String url,byte[] token,int nonce,PublicKey Tpub,PublicKey Spub,String ua,PrivateKey Cpri) throws CipherErrorException, UnsupportedEncodingException {

        Gson gson = new Gson();
        // generate the EToken
        String EToken = Utils.generateEtoken(token,nonce,Tpub);
        // generate T
        int t = SecurityFunctions.generateRandom();
        String T = Utils.base64Encode((SecurityFunctions.encryptAsymmetric(Spub,
                ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(t).array())));
        Map<String,Object> map = new HashMap<>();

        Map<String,String> tokenidmap = new HashMap<>();
        tokenidmap.put("tokenid",tokenid);
        String payload = gson.toJson(tokenidmap);

        map.put("payload",payload);
        map.put("EToken",EToken);
        map.put("T",T);
        String json = gson.toJson(map);

        String res = httpUtil.getJsonData(json,url,ua);

        Map<String,String> result = new Gson().fromJson(res,new TypeToken<Map<String,String>>(){}.getType());

        byte[] T1 = SecurityFunctions.decryptAsymmetric(Cpri,Utils.base64Decode(result.get("T")));
        int t1 = ByteBuffer.wrap(T1).order(ByteOrder.LITTLE_ENDIAN).getInt();

        String M2 = result.get("M");
        Message<String> message = new Gson().fromJson(M2,new TypeToken<Message<String>>(){}.getType());

        if(t1 == t+1){
            if(message.isOk()){
                Map<String,Object> map3 = new HashMap<>();
                map3.put("check",0);
                map3.put("message",message.getMessage());
                return gson.toJson(map3);
            } else {
                Map<String,Object> map3 = new HashMap<>();
                map3.put("check",2);
                map3.put("message",message.getMessage());
                return gson.toJson(map3);
            }
        } else {
            Map<String,Object> map3 = new HashMap<>();
            map3.put("check",1);
            map3.put("message",message.getMessage());
            return gson.toJson(map3);
        }
    }

    /**
     * @param {
     *  "EToken": "Base64 encoded Kt public key encrypted token,nonce+1(by client)",
     *  "T": "Base64 encoded Kt public key encrypted challenge number",
     *             }
     * @return {
     * "check": "0:success/1:timestamp error/2:Authentication failed"
     * "message" : "succuess/timestamp error/Authentication failed"
     * }
     */

    public String regenerateKeys(String url,byte[] token,int nonce,PublicKey Tpub,PublicKey Spub,String ua,PrivateKey Cpri) throws CipherErrorException, UnsupportedEncodingException {
        Gson gson = new Gson();
        // generate the EToken
        String EToken = Utils.generateEtoken(token,nonce,Tpub);

        // generate T
        int t = SecurityFunctions.generateRandom();
        String T = Utils.base64Encode((SecurityFunctions.encryptAsymmetric(Spub,
                ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(t).array())));
        Map<String,Object> map = new HashMap<>();
        map.put("EToken",EToken);
        map.put("T",T);
        String json = gson.toJson(map);
        String res = httpUtil.getJsonData(json,url,ua);
        Map<String,String> result = new Gson().fromJson(res,new TypeToken<Map<String,String>>(){}.getType());

        byte[] T1 = SecurityFunctions.decryptAsymmetric(Cpri,Utils.base64Decode(result.get("T")));
        int t1 = ByteBuffer.wrap(T1).order(ByteOrder.LITTLE_ENDIAN).getInt();

        String M2 = result.get("M");
        Message<String> message = new Gson().fromJson(M2,new TypeToken<Message<String>>(){}.getType());

        if(t1 == t+1){
            if(message.isOk()){
                Map<String,Object> map3 = new HashMap<>();
                map3.put("check",0);
                map3.put("message",message.getMessage());
                return gson.toJson(map3);
            } else {
                Map<String,Object> map3 = new HashMap<>();
                map3.put("check",2);
                map3.put("message",message.getMessage());
                return gson.toJson(map3);
            }
        } else {
            Map<String,Object> map3 = new HashMap<>();
            map3.put("check",1);
            map3.put("message",message.getMessage());
            return gson.toJson(map3);
        }
    }


}


