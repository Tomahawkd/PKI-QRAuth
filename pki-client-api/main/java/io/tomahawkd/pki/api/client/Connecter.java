package io.tomahawkd.pki.api.client;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.sun.scenario.effect.impl.sw.sse.SSEBlend_ADDPeer;
import io.tomahawkd.pki.api.client.util.SecurityFunctions;
import io.tomahawkd.pki.api.client.util.Utils;
import io.tomahawkd.pki.api.client.util.httpUtil;

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
import java.util.Map;

public class Connecter{


    /**
     * @param  {}
     * @return
     * {"K": "Kt public",}
     */
    public String getAuthenticationServerPublicKey(){




        String uri = "39.106.80.38:22222/keys/auth/pubkey";
        try {

            URL url = new URL(uri);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setConnectTimeout(5*1000);
            connection.setDoOutput(true); // 设置该连接是可以输出的
            connection.setRequestMethod("GET"); // 设置请求方式
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
            connection.connect();


            InputStream inputStream=connection.getInputStream();
            byte[] data=new byte[1024];
            StringBuffer sb=new StringBuffer();
            int length=0;
            while ((length=inputStream.read(data))!=-1){
                String s=new String(data, Charset.forName("utf-8"));
                sb.append(s);
            }
            String message=sb.toString();
            inputStream.close();
            connection.disconnect();
            return message;
        }
        catch (Exception e){
            return "申请证书出错，请检查您的网络！";
        }


    }

    public String getServerPublicKey(String id){
        String url = "http://192.168.43.192:8000/serverkey/";
        String json = httpUtil.getJsonData(id,url);
        return json;
    }



    /**
     * @param  "The user's username"
     * @param  "The user's passwprd"
     * @return
     * {"K": "Base64 encoded Kc,t encrypted Kc public",
     *  "M": "Base64 encoded Ks public key encrypted result message",
     *  "T": "Base64 encoded Ks public key encrypted challenge number + 1" ,* "KP": "Base64 encoded Kc,t encrypted client key pair" ,
     *  "EToken": "Base64 encoded Kc public key encrypted token, nonce"}
     */


    public String initalizeAuthentication(String user, String pass, PublicKey Tpub,PublicKey Spub) throws Exception{
        String username = user;
        String password = pass;
        Gson gson = new Gson();
        Map<String,Object> map1 = new HashMap<>();
        map1.put("username",username);
        map1.put("password",password);
        String json1 = gson.toJson(map1);
        String temp = new String(String.valueOf(System.currentTimeMillis()));

        //generate the symmetric ky between C and S
        byte[] Kcs = SecurityFunctions.generateRandom(32);
        //generate the symmetric ky between C and T
        byte[] Kct = SecurityFunctions.generateRandom(32);
        //generte the initial vector
        byte[] iv = SecurityFunctions.generateRandom(16);
        String payload = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(Spub,json1.getBytes()));
        Map<String,Object> map2 = new HashMap<>();
        map2.put("Kcs",Kcs);
        map2.put("time",temp);
        String json2 = gson.toJson(map2);
        String S = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(Spub,json2.getBytes()));
        String K = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(Tpub,Kct));
        String IV = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(Tpub,iv));

        Map<String,Object> map = new HashMap<>();
        map.put("payload",payload);
        map.put("S",S);
        map.put("K",K);
        map.put("iv",IV);
        String json = gson.toJson(map);


        String uri = "39.106.80.38:22222/keys/auth/pubkey";
        String res = httpUtil.getJsonData(json,uri);




            Map<String, String> result = Utils.wrapMapFromJson(res);
            String[] kp =
                    new String(SecurityFunctions.decryptSymmetric(Kct, iv, Utils.base64Decode(result.get("KP"))))
                            .split(";");
            KeyPair keyPair = SecurityFunctions.readKeysFromString(kp[1], kp[0]);
            byte[] etoken = SecurityFunctions.decryptAsymmetric(keyPair.getPrivate(),
                    Utils.base64Decode(result.get("EToken")));
            int nonce = ByteBuffer.wrap(etoken).order(ByteOrder.LITTLE_ENDIAN).getInt();
            byte[] token = new byte[etoken.length - Integer.BYTES];
            System.arraycopy(etoken, Integer.BYTES, token, 0, etoken.length - Integer.BYTES);

            String tR = result.get("T");
            int tRes = ByteBuffer.wrap(SecurityFunctions.decryptAsymmetric(keyPair.getPrivate(), Utils.base64Decode(tR)))
                    .order(ByteOrder.LITTLE_ENDIAN).getInt();
            //assertThat(tRes).isEqualTo(t + 1);

            Map<String,Object> re = new HashMap<>();
            re.put("nonce",nonce);
            re.put("Token",token);
            re.put("Cpri",keyPair.getPrivate());
            re.put("Cpub",keyPair.getPublic());

            return gson.toJson(re);
        }






    /**
     * @param data {"K": "Base64 encoded Kt public key encrypted Kc, t",
     *  		   "id": "Base64 encoded Kt public key encrypted userid&systemid" ,
     *			   "T": "Base64 encoded Kt public key encrypted challenge number"}
     * @return
     * {"K": "Base64 encoded Kc,t encrypted Kc public",
     *  "M": "Base64 encoded Ks public key encrypted result message",
     *  "T": "Base64 encoded Ks public key encrypted challenge number + 1" ,* "KP": "Base64 encoded Kc,t encrypted client key pair" ,
     *  "EToken": "Base64 encoded Kc public key encrypted token, nonce"}
     */

    public String interactAuthentication(String data,PublicKey Tpub,PublicKey Spub,byte[] token,int nonce,PrivateKey Cpri) throws Exception{
        Gson gson = new Gson();

        String payload = Utils.base64Encode(data.getBytes());
        byte[] tokenArr = ByteBuffer.allocate(token.length + Integer.BYTES)
                .order(ByteOrder.LITTLE_ENDIAN).putInt(nonce).put(token).array();
        String etokenReq = Utils.base64Encode(
                SecurityFunctions.encryptAsymmetric(Tpub, tokenArr));
        int tReq = SecurityFunctions.generateRandom();
        String tStringReq = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(Spub,
                ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(tReq).array()));
        Map<String, String> reqMap = new HashMap<>();
        reqMap.put("payload",payload);
        reqMap.put("EToken", etokenReq);
        reqMap.put("T", tStringReq);
        String json = new Gson().toJson(reqMap);



        String uri = "39.106.80.38:22222/keys/auth/pubkey";
        String res = httpUtil.getJsonData(json,uri);


//

            Map<String, String> resultAuth = Utils.wrapMapFromJson(res);
            System.out.println(resultAuth.get("M"));

            String tRes2 = resultAuth.get("T");
            int tRes2Int = ByteBuffer.wrap(SecurityFunctions.decryptAsymmetric(Cpri, Utils.base64Decode(tRes2)))
                    .order(ByteOrder.LITTLE_ENDIAN).getInt();
            //assertThat(tRes2Int).isEqualTo(tReq + 1);
            int check = 1;
            if(tRes2Int!=tReq+1){
                check = 0;
            }
            String payload_re = Utils.base64Decode(resultAuth.get("payload")).toString();

            Map<String,Object> result = new HashMap<>();
            result.put("check",check);
            result.put("data",payload_re);
            return gson.toJson(result);
        }


    public String updateQRStatus(String Token, String nounce1, String nounce2, PublicKey Tpub, PublicKey Spub, PrivateKey Cpri) throws Exception{
        Gson gson = new Gson();
        Map<String,Object> map1 = new HashMap<>();
        map1.put("Token",Token);
        map1.put("nonuce1",nounce1+"1");
        String json1 = gson.toJson(map1);
        String EToken = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(Tpub,json1.getBytes()));
        String temp = new String(String.valueOf(System.currentTimeMillis()));
        String n = Utils.base64Encode(SecurityFunctions.decryptAsymmetric(Cpri,nounce2.getBytes()));
        Map<String,Object> map2 = new HashMap<>();
        map2.put("type",1);
        map2.put("N",n);
        String M = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(Tpub,gson.toJson(map2).getBytes()));

        String T = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(Spub,temp.getBytes()));
        Map<String,Object> map = new HashMap<>();
        map.put("M",M);
        map.put("EToken",EToken);
        map.put("T",T);
        String json = gson.toJson(map);
        String uri = "39.106.80.38:22222/keys/auth/pubkey";
        String res = httpUtil.getJsonData(json,uri);
        return res;

    }

    public String updateQRStatusConfirm(String Token, String nounce1, String nounce2, PublicKey Tpub, PublicKey Spub, PrivateKey Cpri) throws Exception{
        Gson gson = new Gson();
        Map<String,Object> map1 = new HashMap<>();
        map1.put("Token",Token);
        map1.put("nonuce1",nounce1+"1");
        String json1 = gson.toJson(map1);
        String EToken = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(Tpub,json1.getBytes()));
        String temp = new String(String.valueOf(System.currentTimeMillis()));
        Map<String,Object> map2 = new HashMap<>();
        map2.put("type",2);

        String M = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(Tpub,gson.toJson(map2).getBytes()));
        String T = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(Spub,temp.getBytes()));
        Map<String,Object> map = new HashMap<>();
        map.put("M",M);
        map.put("EToken",EToken);
        map.put("T",T);
        String json = gson.toJson(map);
        String uri = "39.106.80.38:22222/keys/auth/pubkey";
        String res = httpUtil.getJsonData(json,uri);
        return res;

    }




}



