package io.tomahawkd.pki.api.client;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.reflect.TypeToken;
import com.sun.scenario.effect.impl.sw.sse.SSEBlend_ADDPeer;
import io.tomahawkd.pki.api.client.exceptions.*;
import io.tomahawkd.pki.api.client.util.SecurityFunctions;
import io.tomahawkd.pki.api.client.util.Utils;
import io.tomahawkd.pki.api.client.util.httpUtil;
import io.tomahawkd.pki.api.client.util.Utils;
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Connecter{

    /**
     * param {null}
     * return Tpub
     *
     */
    public String getAuthenticationServerPublicKey(String ua){

        String uri = "http://192.168.43.159/key/dist/tpub";
        return httpUtil.getJsonData(uri,ua);


    }

    public String getServerPublicKey(String id,String ua){
        String uri = "http://192.168.43.192:8000/serverkey/";
        String a = httpUtil.getJsonData(id,uri,ua);
        return a;


    }



    /**
     * @param  {
     *     "payload" : "Base64 encoded Ks public key encrypted data message",
     *     "S" : "Base64 encoded Ks public key encrypted Timestamp and Kcs",
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


    public String initalizeAuthentication(String user, String pass, PublicKey Tpub,PublicKey Spub,String ua) throws Exception{


        String username = user;
        String password = pass;
        Gson gson = new Gson();
        Map<String,Object> map1 = new HashMap<>();
        map1.put("username",username);
        map1.put("password",password);
        String json1 = gson.toJson(map1);
        int t = SecurityFunctions.generateRandom();

        //generate the symmetric ky between C and T
        byte[] Kct = SecurityFunctions.generateRandom(32);
        //generte the initial vector
        byte[] iv = SecurityFunctions.generateRandom(16);
        String payload = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(Spub,json1.getBytes()));
        //May cause exceptions!!!!!!!!!!!!!!!!!!!!!
        String S = new String((SecurityFunctions.encryptAsymmetric(Spub,
                ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(t).array())),"UTF-8");
        String K = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(Tpub,Kct));
        String IV = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(Tpub,iv));

        Map<String,Object> map = new HashMap<>();
        map.put("payload",payload);
        map.put("S",S);
        map.put("K",K);
        map.put("iv",IV);
        String json = gson.toJson(map);
        String uri = "http://192.168.43.192:8000/serverkey/";
        String res = httpUtil.getJsonData(json,uri,ua);
        Map<String, String> result =
                new Gson().fromJson(res, new TypeToken<Map<String, String>>() {
                }.getType());
            //Map<String, String> result = Utils.wrapMapFromJson(res);
        String m = new String(result.get("M"));
        Map<String,Object> message = new Gson().fromJson(m,new TypeToken<Map<String,Integer>>(){}.getType());

        String[] kp =
                new String(SecurityFunctions.decryptSymmetric(Kct, iv, Utils.base64Decode(result.get("KP"))))
                        .split(";");
        KeyPair keyPair = SecurityFunctions.readKeysFromString(kp[1], kp[0]);
        // 收到的T
        String T = new String(SecurityFunctions.decryptAsymmetric(keyPair.getPrivate(),new String(Utils.base64Decode(result.get("T")),"UTF-8").getBytes()));
        // 转化
        int t1 = ByteBuffer.wrap(T.getBytes()).order(ByteOrder.LITTLE_ENDIAN).getInt();
        //check(0:true,1:time check error,2:time check true,status error)
        if(t1 == t+1){
            if((int)message.get("status") == 0){

                byte[] etoken = SecurityFunctions.decryptAsymmetric(keyPair.getPrivate(),
                        Utils.base64Decode(result.get("EToken")));
                int nonce = ByteBuffer.wrap(etoken).order(ByteOrder.LITTLE_ENDIAN).getInt();

                byte[] token = new byte[etoken.length - Integer.BYTES];
                System.arraycopy(etoken, Integer.BYTES, token, 0, etoken.length - Integer.BYTES);

                Map<String,Object> re = new HashMap<>();
                re.put("nonce",nonce);
                re.put("Token",token);
                re.put("Cpri",keyPair.getPrivate());
                re.put("Cpub",keyPair.getPublic());
                re.put("check",0);
                re.put("message","success");
                return gson.toJson(re);
            }
            else {
                Map<String,Object> map3 = new HashMap<>();
                map3.put("check",2);
                map3.put("message",(String)message.get("message"));
                return gson.toJson(map3);
            }
        } else {
            Map<String,Object> re = new HashMap<>();
            re.put("check",1);
            re.put("message","timestamp error!");
            return  gson.toJson(re);
        }


    }






    /**
     * @param  {
     *     "payload" : "Base64 encoded Ks public key encrypted data message",
     *     "EToken" : "Base64 encoded Kt public key encrypted token,nonce+1",
     *     "T" : "Base64 encoded Ks public key encrypted challenge number",
     * }
     * @return
     * { "T" : "Base64 encoded Kc public key encrypted challenge number",
     *   "payload" : "Base64 encoded Kc public key encrypted data message"
     *  }
     */

    public String interactAuthentication(String data,PublicKey Tpub,PublicKey Spub,byte[] token,int nonce,PrivateKey Cpri,String ua) throws Exception{
        Gson gson = new Gson();

        String payload = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(Spub,data.getBytes()));
        byte[] tokenArr = ByteBuffer.allocate(token.length + Integer.BYTES)
                .order(ByteOrder.LITTLE_ENDIAN).putInt(nonce+1).put(token).array();
        String etokenReq = Utils.base64Encode(
                SecurityFunctions.encryptAsymmetric(Tpub, tokenArr));

        int t = SecurityFunctions.generateRandom();
        String tStringReq = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(Spub,
                ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(t).array()));

        Map<String, String> reqMap = new HashMap<>();
        reqMap.put("payload",payload);
        reqMap.put("EToken", etokenReq);
        reqMap.put("T", tStringReq);
        String json = new Gson().toJson(reqMap);



        String uri = "http://192.168.43.192:8000/serverkey/";
        String res = httpUtil.getJsonData(json,uri,ua);

        Map<String,String> result = new Gson().fromJson(res, new TypeToken<Map<String, String>>() {}.getType());
        String m = new String(Utils.base64Decode(result.get("M")),"UTF-8");
        Map<String,Object> message = new Gson().fromJson(m,new TypeToken<Map<String,Integer>>(){}.getType());

        String T = new String(SecurityFunctions.decryptAsymmetric(Cpri,new String(Utils.base64Decode(result.get("T")),"UTF-8").getBytes()));
        int t1 = ByteBuffer.wrap(T.getBytes()).order(ByteOrder.LITTLE_ENDIAN).getInt();
        if(t1 == t+1){
            if ((int)message.get("status")==0) {
                String data1 = String.valueOf(Utils.base64Decode(String.valueOf(SecurityFunctions.decryptAsymmetric(Cpri,result.get("payload").getBytes()))));
                Map<String, Object> map3 = new HashMap<>();
                map3.put("data",data1);
                map3.put("check", 0);
                map3.put("message","sucess");
                return gson.toJson(map3);
            }else {
                Map<String, Object> map3 = new HashMap<>();
                map3.put("check", 2);
                map3.put("message", "认证错误");
                return gson.toJson(map3);
            }
        }
        else {
            Map<String, Object> map4 = new HashMap<>();
            map4.put("check", 1);
            map4.put("mssage", "time check error!");
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
     *            "check" : "0:success/1:timestamp error/2:Authentication failed"
     *             "message" : "succuess/timestamp error/Authentication failed"
     *          }
     */
    public String updateQRStatus(byte[] token, int nonce, String nonce2, PublicKey Tpub, PublicKey Spub, PrivateKey Cpri,String ua) throws Exception{
        Gson gson = new Gson();
        // generate the EToken
        byte[] tokenArr = ByteBuffer.allocate(token.length + Integer.BYTES)
                .order(ByteOrder.LITTLE_ENDIAN).putInt(nonce+1).put(token).array();
        String etokenReq = Utils.base64Encode(
                SecurityFunctions.encryptAsymmetric(Tpub, tokenArr));
        String EToken = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(Tpub,etokenReq.getBytes()));
        //generate T
        int t = SecurityFunctions.generateRandom();
        String T = new String((SecurityFunctions.encryptAsymmetric(Spub,
                ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(t).array())),"UTF-8");

        //generate N
        String N = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(Tpub,nonce2.getBytes()));

        Map<String,Object> M = new HashMap<>();
        M.put("status",1);
        M.put("message",N);
        String M1 = gson.toJson(M);

        Map<String,Object> map = new HashMap<>();
        map.put("EToken",EToken);
        map.put("T",T);
        map.put("M",M1);
        String json = gson.toJson(map);
        String uri = "39.106.80.38:22222/keys/auth/pubkey";
        String res = httpUtil.getJsonData(json,uri,ua);
        Map<String,String> result = new Gson().fromJson(res,new TypeToken<Map<String,String>>(){}.getType());

        String m = result.get("M");
        Map<String,Object> m1 = new Gson().fromJson(m,new TypeToken<Map<String,Object>>(){}.getType());

        String T1 = new String(SecurityFunctions.decryptAsymmetric(Cpri,new String(Utils.base64Decode(result.get("T")),"UTF-8").getBytes()));
        int t1 = ByteBuffer.wrap(T.getBytes()).order(ByteOrder.LITTLE_ENDIAN).getInt();
        if(t1 == t+1){
            if((int)m1.get("status")==0){
                Map<String,Object> map2 = new HashMap<>();
                map2.put("check",0);
                map2.put("message","Success");
                return gson.toJson(map2);
            } else {
                Map<String,Object> map3 = new HashMap<>();
                map3.put("check",2);
                map3.put("message","验证扫描失败！");
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
     * @param  { "M": {
     *             "status": 2:",
     *             "message":"1:true/0:false"
     *             }
     *             "EToken": "Base64 encoded Kt public key encrypted token,nonce",
     *             "T": "Base64 encoded Kt public key encrypted challenge number",
     *             }
     * @return {
     *          {
     *            "check" : "0:success/1:timestamp error/2:Authentication failed"
     *             "message" : "succuess/timestamp error/Authentication failed"
     *          }
     */

    public String updateQRStatusConfirm(byte[] token, int nonce, String nounce2, PublicKey Tpub, PublicKey Spub, PrivateKey Cpri,int confirm,String ua) throws Exception{
        Gson gson = new Gson();
        // generate the EToken
        byte[] tokenArr = ByteBuffer.allocate(token.length + Integer.BYTES)
                .order(ByteOrder.LITTLE_ENDIAN).putInt(nonce+1).put(token).array();
        String etokenReq = Utils.base64Encode(
                SecurityFunctions.encryptAsymmetric(Tpub, tokenArr));
        String EToken = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(Tpub,etokenReq.getBytes()));
        // generate T
        int t = SecurityFunctions.generateRandom();
        String T = new String((SecurityFunctions.encryptAsymmetric(Spub,
                ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(t).array())),"UTF-8");


        Map<String,Object> map2 = new HashMap<>();
        map2.put("status",2);
        map2.put("message",confirm);
        String M = gson.toJson(map2);

        Map<String,Object> map = new HashMap<>();
        map.put("M",M);
        map.put("EToken",EToken);
        map.put("T",T);
        String json = gson.toJson(map);
        String uri = "39.106.80.38:22222/keys/auth/pubkey";
        String res = httpUtil.getJsonData(json,uri,ua);
        Map<String,String> result = new Gson().fromJson(res,new TypeToken<Map<String,String>>(){}.getType());        //assertThat(result.get("M")).contains("\"status\":0");
        //if(result.get("M").getStatu())

        String T1 = new String(SecurityFunctions.decryptAsymmetric(Cpri,new String(Utils.base64Decode(result.get("T")),"UTF-8").getBytes()));
        int t1 = ByteBuffer.wrap(T.getBytes()).order(ByteOrder.LITTLE_ENDIAN).getInt();
        String M2 = new String(SecurityFunctions.decryptAsymmetric(Cpri,new String(Utils.base64Decode(result.get("M")),"UTF-8").getBytes()));
        Map<String,Object> M3 = new Gson().fromJson(M2,new TypeToken<Map<String,String>>(){}.getType());        //assertThat(result.get("M")).contains("\"status\":0");

        if(t1 == t+1){
            if((int)M3.get("status")==0){
                Map<String,Object> map3 = new HashMap<>();
                map3.put("check",0);
                map3.put("message","Success");
                return gson.toJson(map3);
            } else {
                Map<String,Object> map3 = new HashMap<>();
                map3.put("check",2);
                map3.put("message","验证登录失败！");
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
     * "M": "
     * {
     * "status": "0:success/1:timestamp error/2:Authentication failed"
     * "message": "service message"
     * }
     */

    public String getLog(byte[] token,int nonce,PublicKey Tpub,PublicKey Spub,String ua,PrivateKey Cpri) throws CipherErrorException, UnsupportedEncodingException {
        Gson gson = new Gson();
        // generate the EToken
        byte[] tokenArr = ByteBuffer.allocate(token.length + Integer.BYTES)
                .order(ByteOrder.LITTLE_ENDIAN).putInt(nonce+1).put(token).array();
        String etokenReq = Utils.base64Encode(
                SecurityFunctions.encryptAsymmetric(Tpub, tokenArr));
        String EToken = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(Tpub,etokenReq.getBytes()));
        // generate T
        int t = SecurityFunctions.generateRandom();
        String T = new String((SecurityFunctions.encryptAsymmetric(Spub,
                ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(t).array())),"UTF-8");
        Map<String,Object> map = new HashMap<>();
        map.put("EToken",EToken);
        map.put("T",T);
        String json = gson.toJson(map);

        String uri = "39.106.80.38:22222/keys/auth/pubkey";
        String res = httpUtil.getJsonData(json,uri,ua);
        Map<String,String> result = new Gson().fromJson(res,new TypeToken<Map<String,String>>(){}.getType());

        String T1 = new String(SecurityFunctions.decryptAsymmetric(Cpri,new String(Utils.base64Decode(result.get("T")),"UTF-8").getBytes()));
        int t1 = ByteBuffer.wrap(T.getBytes()).order(ByteOrder.LITTLE_ENDIAN).getInt();
        String M2 = new String(SecurityFunctions.decryptAsymmetric(Cpri,new String(Utils.base64Decode(result.get("M")),"UTF-8").getBytes()));
        Map<String,Object> M3 = new Gson().fromJson(M2,new TypeToken<Map<String,String>>(){}.getType());
        if(t1 == t+1){
            if((int)M3.get("status")==0){
                // *******************************************
                //List<UserLogModel>
                List<Map<String,String>> logList = (List) M3.get("message");

                Map<String,Object> map3 = new HashMap<>();
                map3.put("check",0);
                map3.put("message","Success");
                map3.put("loglist",logList);


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
     * "M": "
     * {
     * "status": "0:success/1:timestamp error/2:Authentication failed"
     * "message": "service message"
     * }
     */

    public String initTokenList(byte[] token,int nonce,PublicKey Tpub,PublicKey Spub,String ua,PrivateKey Cpri) throws CipherErrorException, UnsupportedEncodingException {
        Gson gson = new Gson();
        // generate the EToken
        byte[] tokenArr = ByteBuffer.allocate(token.length + Integer.BYTES)
                .order(ByteOrder.LITTLE_ENDIAN).putInt(nonce+1).put(token).array();
        String etokenReq = Utils.base64Encode(
                SecurityFunctions.encryptAsymmetric(Tpub, tokenArr));
        String EToken = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(Tpub,etokenReq.getBytes()));
        // generate T
        int t = SecurityFunctions.generateRandom();
        String T = new String((SecurityFunctions.encryptAsymmetric(Spub,
                ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(t).array())),"UTF-8");
        Map<String,Object> map = new HashMap<>();
        map.put("EToken",EToken);
        map.put("T",T);
        String json = gson.toJson(map);

        String uri = "39.106.80.38:22222/keys/auth/pubkey";
        String res = httpUtil.getJsonData(json,uri,ua);
        Map<String,String> result = new Gson().fromJson(res,new TypeToken<Map<String,String>>(){}.getType());
        String T1 = new String(SecurityFunctions.decryptAsymmetric(Cpri,new String(Utils.base64Decode(result.get("T")),"UTF-8").getBytes()));
        int t1 = ByteBuffer.wrap(T.getBytes()).order(ByteOrder.LITTLE_ENDIAN).getInt();
        String M2 = new String(SecurityFunctions.decryptAsymmetric(Cpri,new String(Utils.base64Decode(result.get("M")),"UTF-8").getBytes()));
        Map<String,Object> M3 = new Gson().fromJson(M2,new TypeToken<Map<String,String>>(){}.getType());
        if(t1 == t+1){
            if((int)M3.get("status")==0){
                // *******************************************

                Map<String,Object> map3 = new HashMap<>();
                map3.put("check",0);
                map3.put("message","Success");
                return gson.toJson(map3);
            } else {
                Map<String,Object> map3 = new HashMap<>();
                map3.put("check",2);
                map3.put("message","Token列表获取失败，请重试！");
                return gson.toJson(map3);
            }
        } else {
            Map<String,Object> map3 = new HashMap<>();
            map3.put("check",1);
            map3.put("message","time check error!");
            return gson.toJson(map3);
        }

    }

    public String revokeToken(byte[] token,int nonce,PublicKey Tpub,PublicKey Spub,String ua,PrivateKey Cpri) throws CipherErrorException, UnsupportedEncodingException {

        Gson gson = new Gson();
        // generate the EToken
        byte[] tokenArr = ByteBuffer.allocate(token.length + Integer.BYTES)
                .order(ByteOrder.LITTLE_ENDIAN).putInt(nonce+1).put(token).array();
        String etokenReq = Utils.base64Encode(
                SecurityFunctions.encryptAsymmetric(Tpub, tokenArr));
        String EToken = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(Tpub,etokenReq.getBytes()));
        // generate T
        int t = SecurityFunctions.generateRandom();
        String T = new String((SecurityFunctions.encryptAsymmetric(Spub,
                ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(t).array())),"UTF-8");
        Map<String,Object> map = new HashMap<>();
        map.put("EToken",EToken);
        map.put("T",T);
        String json = gson.toJson(map);

        String uri = "39.106.80.38:22222/keys/auth/pubkey";
        String res = httpUtil.getJsonData(json,uri,ua);
        Map<String,String> result = new Gson().fromJson(res,new TypeToken<Map<String,String>>(){}.getType());
        String T1 = new String(SecurityFunctions.decryptAsymmetric(Cpri,new String(Utils.base64Decode(result.get("T")),"UTF-8").getBytes()));
        int t1 = ByteBuffer.wrap(T.getBytes()).order(ByteOrder.LITTLE_ENDIAN).getInt();
        String M2 = new String(SecurityFunctions.decryptAsymmetric(Cpri,new String(Utils.base64Decode(result.get("M")),"UTF-8").getBytes()));
        Map<String,Object> M3 = new Gson().fromJson(M2,new TypeToken<Map<String,String>>(){}.getType());
        if(t1 == t+1){
            if((int)M3.get("status")==0){
                // *******************************************

                Map<String,Object> map3 = new HashMap<>();
                map3.put("check",0);
                map3.put("message","Success");
                return gson.toJson(map3);
            } else {
                Map<String,Object> map3 = new HashMap<>();
                map3.put("check",2);
                map3.put("message","Token列表获取失败，请重试！");
                return gson.toJson(map3);
            }
        } else {
            Map<String,Object> map3 = new HashMap<>();
            map3.put("check",1);
            map3.put("message","time check error!");
            return gson.toJson(map3);
        }
    }

    public String regenerateKeys(byte[] token,int nonce,PublicKey Tpub,PublicKey Spub,String ua,PrivateKey Cpri) throws CipherErrorException, UnsupportedEncodingException {
        Gson gson = new Gson();
        // generate the EToken
        byte[] tokenArr = ByteBuffer.allocate(token.length + Integer.BYTES)
                .order(ByteOrder.LITTLE_ENDIAN).putInt(nonce+1).put(token).array();
        String etokenReq = Utils.base64Encode(
                SecurityFunctions.encryptAsymmetric(Tpub, tokenArr));
        String EToken = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(Tpub,etokenReq.getBytes()));
        // generate T
        int t = SecurityFunctions.generateRandom();
        String T = new String((SecurityFunctions.encryptAsymmetric(Spub,
                ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(t).array())),"UTF-8");
        Map<String,Object> map = new HashMap<>();
        map.put("EToken",EToken);
        map.put("T",T);
        String json = gson.toJson(map);

        String uri = "39.106.80.38:22222/keys/auth/pubkey";
        String res = httpUtil.getJsonData(json,uri,ua);
        Map<String,String> result = new Gson().fromJson(res,new TypeToken<Map<String,String>>(){}.getType());
        String T1 = new String(SecurityFunctions.decryptAsymmetric(Cpri,new String(Utils.base64Decode(result.get("T")),"UTF-8").getBytes()));
        int t1 = ByteBuffer.wrap(T.getBytes()).order(ByteOrder.LITTLE_ENDIAN).getInt();
        String M2 = new String(SecurityFunctions.decryptAsymmetric(Cpri,new String(Utils.base64Decode(result.get("M")),"UTF-8").getBytes()));
        Map<String,Object> M3 = new Gson().fromJson(M2,new TypeToken<Map<String,String>>(){}.getType());
        if(t1 == t+1){
            if((int)M3.get("status")==0){
                // *******************************************

                Map<String,Object> map3 = new HashMap<>();
                map3.put("check",0);
                map3.put("message","Success");
                return gson.toJson(map3);
            } else {
                Map<String,Object> map3 = new HashMap<>();
                map3.put("check",2);
                map3.put("message","Token列表获取失败，请重试！");
                return gson.toJson(map3);
            }
        } else {
            Map<String,Object> map3 = new HashMap<>();
            map3.put("check",1);
            map3.put("message","time check error!");
            return gson.toJson(map3);
        }
    }


}



