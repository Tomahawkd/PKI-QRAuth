package io.tomahawkd.pki.api.client;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.sun.scenario.effect.impl.sw.sse.SSEBlend_ADDPeer;
import io.tomahawkd.pki.api.client.util.SecurityFunctions;
import io.tomahawkd.pki.api.client.util.Utils;

import javax.jws.Oneway;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
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

            connection.setDoOutput(true); // 设置该连接是可以输出的
            connection.setRequestMethod("GET"); // 设置请求方式
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");

            BufferedReader br = new BufferedReader(new InputStreamReader(connection.getInputStream(), "utf-8"));
            String line = null;
            StringBuilder result = new StringBuilder();
            while ((line = br.readLine()) != null) { // 读取数据
                result.append(line + "\n");
            }
            connection.disconnect();

            return result.toString();
        }
        catch (Exception e){
            return "连接异常，请重试!";
        }


    }

    public String getServerPublicKey(String id){
        String uri = "39.106.80.38:22222/keys/auth/pubkey";
        URL url = null;
        try {
            url = new URL(uri);
            HttpURLConnection httpURLConnection = (HttpURLConnection) url.openConnection();
            httpURLConnection.setRequestMethod("POST");// 提交模式
            // conn.setConnectTimeout(10000);//连接超时 单位毫秒
            // conn.setReadTimeout(2000);//读取超时 单位毫秒
            // 发送POST请求必须设置如下两行
            httpURLConnection.setDoOutput(true);
            httpURLConnection.setDoInput(true);
            // 获取URLConnection对象对应的输出流
            PrintWriter printWriter = new PrintWriter(httpURLConnection.getOutputStream());
            // 发送请求参数
            printWriter.write(id);//post的参数 xx=xx&yy=yy
            // flush输出流的缓冲
            printWriter.flush();
            //开始获取数据
            BufferedInputStream bis = new BufferedInputStream(httpURLConnection.getInputStream());
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            int len;
            byte[] arr = new byte[1024];
            while((len=bis.read(arr))!= -1){
                bos.write(arr,0,len);
                bos.flush();
            }
            bos.close();
            return bos.toString("utf-8");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;


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
        //generate the seed
        byte[] random = SecurityFunctions.generateRandom(16);
        //generate the symmetric ky between C and S
        byte[] Kcs = SecurityFunctions.generateSymKey(random.toString());
        //generate the symmetric ky between C and T
        byte[] Kct = SecurityFunctions.generateSymKey(random.toString());
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
        URL url = null;
        try {
            url = new URL(uri);
            HttpURLConnection httpURLConnection = (HttpURLConnection) url.openConnection();
            httpURLConnection.setRequestMethod("POST");// 提交模式
            // conn.setConnectTimeout(10000);//连接超时 单位毫秒
            // conn.setReadTimeout(2000);//读取超时 单位毫秒
            // 发送POST请求必须设置如下两行
            httpURLConnection.setDoOutput(true);
            httpURLConnection.setDoInput(true);
            // 获取URLConnection对象对应的输出流
            PrintWriter printWriter = new PrintWriter(httpURLConnection.getOutputStream());
            // 发送请求参数
            printWriter.write(json);//post的参数 xx=xx&yy=yy
            // flush输出流的缓冲
            printWriter.flush();
            //开始获取数据
            BufferedInputStream bis = new BufferedInputStream(httpURLConnection.getInputStream());
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            int len;
            byte[] arr = new byte[1024];
            while((len=bis.read(arr))!= -1){
                bos.write(arr,0,len);
                bos.flush();
            }
            bos.close();
            return bos.toString("utf-8");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;

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

    public String interactAuthentication(String data,PublicKey Tpub,PublicKey Spub,String token,int nonce,String time) throws Exception{
        Gson gson = new Gson();
        String payload = Utils.base64Encode(data.getBytes());
        Map<String,Object> map1 = new HashMap<>();
        map1.put("token",token);
        map1.put("nounce",nonce+1);
        String json1 = gson.toJson(map1);
        byte[] EToken = SecurityFunctions.encryptAsymmetric(Tpub,json1.getBytes());
        byte[] T = SecurityFunctions.encryptAsymmetric(Spub,time.getBytes());

        Map<String,Object> map = new HashMap<>();
        map.put("payload",payload);
        map.put("EToken",EToken);
        map.put("T",T);
        String json = gson.toJson(map);
        String uri = "39.106.80.38:22222/keys/auth/pubkey";
        URL url = null;
        try {
            url = new URL(uri);
            HttpURLConnection httpURLConnection = (HttpURLConnection) url.openConnection();
            httpURLConnection.setRequestMethod("POST");// 提交模式
            // conn.setConnectTimeout(10000);//连接超时 单位毫秒
            // conn.setReadTimeout(2000);//读取超时 单位毫秒
            // 发送POST请求必须设置如下两行
            httpURLConnection.setDoOutput(true);
            httpURLConnection.setDoInput(true);
            // 获取URLConnection对象对应的输出流
            PrintWriter printWriter = new PrintWriter(httpURLConnection.getOutputStream());
            // 发送请求参数
            printWriter.write(json);//post的参数 xx=xx&yy=yy
            // flush输出流的缓冲
            printWriter.flush();
            //开始获取数据
            BufferedInputStream bis = new BufferedInputStream(httpURLConnection.getInputStream());
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            int len;
            byte[] arr = new byte[1024];
            while((len=bis.read(arr))!= -1){
                bos.write(arr,0,len);
                bos.flush();
            }
            bos.close();
            return bos.toString("utf-8");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
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
        URL url = null;
        try {
            url = new URL(uri);
            HttpURLConnection httpURLConnection = (HttpURLConnection) url.openConnection();
            httpURLConnection.setRequestMethod("POST");// 提交模式
            // conn.setConnectTimeout(10000);//连接超时 单位毫秒
            // conn.setReadTimeout(2000);//读取超时 单位毫秒
            // 发送POST请求必须设置如下两行
            httpURLConnection.setDoOutput(true);
            httpURLConnection.setDoInput(true);
            // 获取URLConnection对象对应的输出流
            PrintWriter printWriter = new PrintWriter(httpURLConnection.getOutputStream());
            // 发送请求参数
            printWriter.write(json);//post的参数 xx=xx&yy=yy
            // flush输出流的缓冲
            printWriter.flush();
            //开始获取数据
            BufferedInputStream bis = new BufferedInputStream(httpURLConnection.getInputStream());
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            int len;
            byte[] arr = new byte[1024];
            while((len=bis.read(arr))!= -1){
                bos.write(arr,0,len);
                bos.flush();
            }
            bos.close();
            return bos.toString("utf-8");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
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
        URL url = null;
        try {
            url = new URL(uri);
            HttpURLConnection httpURLConnection = (HttpURLConnection) url.openConnection();
            httpURLConnection.setRequestMethod("POST");// 提交模式
            // conn.setConnectTimeout(10000);//连接超时 单位毫秒
            // conn.setReadTimeout(2000);//读取超时 单位毫秒
            // 发送POST请求必须设置如下两行
            httpURLConnection.setDoOutput(true);
            httpURLConnection.setDoInput(true);
            // 获取URLConnection对象对应的输出流
            PrintWriter printWriter = new PrintWriter(httpURLConnection.getOutputStream());
            // 发送请求参数
            printWriter.write(json);//post的参数 xx=xx&yy=yy
            // flush输出流的缓冲
            printWriter.flush();
            //开始获取数据
            BufferedInputStream bis = new BufferedInputStream(httpURLConnection.getInputStream());
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            int len;
            byte[] arr = new byte[1024];
            while((len=bis.read(arr))!= -1){
                bos.write(arr,0,len);
                bos.flush();
            }
            bos.close();
            return bos.toString("utf-8");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }




}



