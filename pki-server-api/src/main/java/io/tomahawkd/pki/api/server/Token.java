package io.tomahawkd.pki.api.server;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import org.jcp.xml.dsig.internal.dom.Utils;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

public class Token {
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private PublicKey TpublicKey;
    private String Kcs;
    private String systemid = "a5e1fc6f2f4941fe981e0361a99ded64";
    /**
     * @Param data {"payload": "Base64 encoded Ks public key encrypted (username,password)",
     *              "S": "Base64 encoded Ks public key encrypted (Kc,s,time1)",
     *              "K": "Base64 encoded Kt public key encrypted Kc,t",
     *              "D": "Base64 encoded (device,id)"
     *              "iv": "Base64 encoded Kt public key encrypted iv"}
     * @return
     * {"EToken": "Base64 encoded Kc public key encrypted token",
     *  "D": "Base64 encoded device,id "
     *  "M": {"status": (number 0,1,2),"message": "status description"}
     *  "KP": "Base64 encoded Kc,t encrypted (Kc public key,Kc private key)",
     *  "T1": "Base64 encoded Kc public key encrypted (time1+1)"}
     */
    public String acceptInitializeAuthenticationMessage(String body,ThrowableBiFunction<String,String, Integer> callback) throws Exception {
        Map<String, String> bodyData =
                new Gson().fromJson(body, new TypeToken<Map<String, String>>() {
                }.getType());
        Base64.Decoder decoder = Base64.getDecoder();
        String payload = new String(decoder.decode(bodyData.get("payload")),"UTF-8");
        String[] user_pass = payload.split(";");
        String username = user_pass[0];
        String password = user_pass[1];

        int usrid = callback.apply(username,password);
        if(usrid != -1)
            return "{\"M\":{\"status\":4,\"message\":\"user function failed\"}}";

        String eS = new String(decoder.decode(bodyData.get("S")),"UTF-8");
        String time1 = new String(SecurityFunctions.decryptAsymmetric(privateKey,eS.getBytes()));

        String K = new String(decoder.decode(bodyData.get("K")),"UTF-8");
        String iv = new String(decoder.decode(bodyData.get("iv")),"UTF-8");
        int t = SecurityFunctions.generateRandom();
        String time2 = new String((SecurityFunctions.encryptAsymmetric(TpublicKey,
                ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(t).array())),"UTF-8");
        //String time2 = new String(SecurityFunctions.encryptAsymmetric(TpublicKey,String.valueOf(timestamp).getBytes()),"UTF-8");
        String userid = String.valueOf(usrid);     //userid获得
            //systemid获得
        //加密payload userid和systemid
        String idc = userid + ";" + systemid;
        String eidc = new String(SecurityFunctions.encryptAsymmetric(TpublicKey,idc.getBytes()));
        String device = ""; //改
        String id = "";     //改
        String  D = device + ";" + id;
        //encode K,idc,time2
        Base64.Encoder encoder = Base64.getEncoder();
        String encK = encoder.encodeToString(K.getBytes());
        String encid = encoder.encodeToString(iv.getBytes());
        String encidc =  encoder.encodeToString(eidc.getBytes());
        String enctime2 = encoder.encodeToString(time2.getBytes());
        String encD = encoder.encodeToString(D.getBytes());

        String target_url = "/token/init";
        StringBuilder target = new StringBuilder(target_url);
        URL url = new URL(target.toString());
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setDoOutput(true);
        String content = "{\"K\":\"" + encK + "\",\"id\":\"" + encid + "\",\"idc\":\"" + encidc + "\",\"D\":\"" + encD + "\",\"T\":\"" + enctime2 + "\"}";
        OutputStream os = connection.getOutputStream();
        byte[] input = content.getBytes(StandardCharsets.UTF_8);
        os.write(input,0,input.length);
        connection.setConnectTimeout(2000);
        connection.setReadTimeout(2000);
        connection.connect();
        StringBuilder text = new StringBuilder();
        int responseCode = connection.getResponseCode();
        boolean error = false;
        InputStreamReader in;
        if (responseCode == HttpURLConnection.HTTP_OK ||
                responseCode == HttpURLConnection.HTTP_ACCEPTED ||
                responseCode == HttpURLConnection.HTTP_CREATED) {
            in = new InputStreamReader(connection.getInputStream());
        } else {
            in = new InputStreamReader(connection.getErrorStream());
        }
        BufferedReader buff = new BufferedReader(in);
        String line = buff.readLine();
        while (line != null) {
            text.append(line).append("\r\n");
            line = buff.readLine();
        }
        if(error)
            return "{\"M\":{\"status\":3,\"message\":\"" + text.toString() + "\"}}";

        String eresult = text.toString();
        Map<String, String> result =
                new Gson().fromJson(eresult, new TypeToken<Map<String, String>>() {
                }.getType());
        String m = new String(decoder.decode(result.get("M")),"UTF-8");
        Map<String,Object> message = new Gson().fromJson(m,new TypeToken<Map<String,Integer>>(){}.getType());
        if((int)message.get("status") == 0){
            String etoken = result.get("EToken");
            String KP = result.get("KP");
            String T = new String(SecurityFunctions.decryptAsymmetric(privateKey,new String(decoder.decode(result.get("T")),"UTF-8").getBytes()));
            String k = new String(decoder.decode(result.get("K")),"UTF-8");
            PublicKey Kcpub = SecurityFunctions.getPublicKey(k);
            int t1 = ByteBuffer.wrap(T.getBytes()).order(ByteOrder.LITTLE_ENDIAN).getInt();
            if((t1 == t + 1)){
                int tem = ByteBuffer.wrap(time1.getBytes()).order(ByteOrder.LITTLE_ENDIAN).getInt();
                String time = new String((SecurityFunctions.encryptAsymmetric(Kcpub,
                        ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(tem).array())),"UTF-8");
                return "{\"EToken\":\"" + etoken + "\",\"KP\":\"" + KP + "\",\"T1\":\"" + Base64.getEncoder().encodeToString(time.getBytes()) + "\",\"M\":{\"status\":" + 0 + ",\"message\":\"success\"}}";
            }
            return "{\"M\":{\"status\":1,\"message\":\"time authentication failed\"}}";
        }
        return "{\"M\":{\"status\":2,\"message\":\"" + message.get("message") + "\"}}";
    }

    /**
     * @Param data {"payload": "Base64 encoded data",
     *              "EToken": "Base64 encoded Kt public key encrypted (token,nonce+1)",
     *              "systemid": "Base64 encoded Kt public key encrypted systemid"
     *              "T": "Base64 encoded Ks public key encrypted time1"}
     * @return
     * {"T": "Base64 encoded Kc public key encrypted token",
     *  "M": {"status": (number 0,1,2),"message": "status description"}
     *  "payload": "Base64 encoded Kc public key encrypted data"}
     */
    public String autuentication(String body,ReturnDataFunction<String,String,String> callback) throws Exception {
        Map<String,String> bodydata = new Gson().fromJson(body,new TypeToken<Map<String,String>>(){}.getType());
        Base64.Decoder decoder = Base64.getDecoder();
        String payload = new String(decoder.decode(bodydata.get("payload")),"UTF-8");
        String etoken = bodydata.get("EToken");
        String T = bodydata.get("T");
        String time1 = new String(SecurityFunctions.decryptAsymmetric(privateKey,T.getBytes()),"UTF-8");
        int t = SecurityFunctions.generateRandom();
        String time2 = new String((SecurityFunctions.encryptAsymmetric(TpublicKey,
                ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(t).array())),"UTF-8");
        String esystemid = Base64.getEncoder().encodeToString(systemid.getBytes());

        String target_url = "/token/validate";
        StringBuilder target = new StringBuilder(target_url);
        URL url = new URL(target.toString());
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setDoOutput(true);
        String content = "{\"EToken\":\"" + etoken + "\",\"systemid\":\"" + esystemid + "\",\"T\":\"" + Base64.getEncoder().encodeToString(time2.getBytes()) +  "\"}";
        OutputStream os = connection.getOutputStream();
        byte[] input = content.getBytes(StandardCharsets.UTF_8);
        os.write(input,0,input.length);
        connection.setConnectTimeout(2000);
        connection.setReadTimeout(2000);
        connection.connect();
        StringBuilder text = new StringBuilder();
        int responseCode = connection.getResponseCode();
        boolean error = false;
        InputStreamReader in;
        if (responseCode == HttpURLConnection.HTTP_OK ||
                responseCode == HttpURLConnection.HTTP_ACCEPTED ||
                responseCode == HttpURLConnection.HTTP_CREATED) {
            in = new InputStreamReader(connection.getInputStream());
        } else {
            in = new InputStreamReader(connection.getErrorStream());
        }
        BufferedReader buff = new BufferedReader(in);
        String line = buff.readLine();
        while (line != null) {
            text.append(line).append("\r\n");
            line = buff.readLine();
        }
        if(error)
            return "{\"M\":{\"status\":2,\"message\":\"" + text.toString() + "\"}}";

        String ereceive = text.toString();
        Map<String,String> receive = new Gson().fromJson(ereceive, new TypeToken<Map<String, String>>() {}.getType());
        String M = new String(decoder.decode(receive.get("M")),"UTF-8");
        //Map<String,Object> message = new Gson().fromJson(M,new TypeToken<Map<String,Integer>>(){}.getType());
        String K = new String(decoder.decode(receive.get("K")),"UTF-8");
        String T2 = new String(SecurityFunctions.decryptAsymmetric(privateKey,decoder.decode(receive.get("T"))),"UTF-8");
        int t1 = ByteBuffer.wrap(T2.getBytes()).order(ByteOrder.LITTLE_ENDIAN).getInt();
        PublicKey Kcpub = SecurityFunctions.getPublicKey(K);
        if(t1 == t + 1){
            String data = callback.apply(M,payload);
            int tem = ByteBuffer.wrap(time1.getBytes()).order(ByteOrder.LITTLE_ENDIAN).getInt();
            String time = new String((SecurityFunctions.encryptAsymmetric(Kcpub,
                    ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(tem).array())),"UTF-8");
            //String time = new String(SecurityFunctions.encryptAsymmetric(Kcpub,String.valueOf(Long.parseLong(time1) + 1).getBytes()),"UTF-8");
            Base64.Encoder encoder = Base64.getEncoder();
            String Payload = encoder.encodeToString(data.getBytes());
            return "{\"M\":{\"status\":0,\"message\":authentication success\"},\"T\":\"" + encoder.encodeToString(time.getBytes()) + "\",\"payload\":\"" + Payload + "\"}";
        }
        return "{\"M\":{\"status\":1,\"message\":time authentiaction failed\"}";
    }

    /**
     * @Param data {"EToken": "Base64 encoded Kt public key encrypted (Token,nonce+1)",
     *              "N": "Base64 encoded Kt public key encrypted nonce2",
     *              "systemid": "Base64 encoded systemid",
     *              "T": "Base64 encoded Ks public key encrypted time1"}
     * @return
     * {"T": "Base64 encoded Kc public key encrypted token",
     *  "M": {"status": (number 0,1,2),"message": "status description"}
     *  "payload": "Base64 encoded Kc public key encrypted data"}
     */
    public String scanner(String body) throws Exception {
        Base64.Decoder decoder = Base64.getDecoder();
        Map<String,String> bodydata = new Gson().fromJson(body,new TypeToken<Map<String,String>>(){}.getType());
        String EToken = bodydata.get("EToken");
        String N = bodydata.get("N");
        String time1 = new String(SecurityFunctions.decryptAsymmetric(privateKey,decoder.decode(bodydata.get("T").getBytes())),"UTF-8");
        int time2 = SecurityFunctions.generateRandom();
        String time = new String(SecurityFunctions.encryptAsymmetric(TpublicKey,ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(time2).array()),"UTF-8");
        String sysid = Base64.getEncoder().encodeToString(systemid.getBytes());
        String content = "{\"M\":{\"type\":1,\"N\":\"" + N + "\"},\"systemid\":\"" + sysid + "\"," +
                "\"EToken\":\"" + EToken + "\",\"T\":\"" + Base64.getEncoder().encodeToString(time.getBytes()) + "\"}";
        String target_url = "/qr/query";
        StringBuilder target = new StringBuilder(target_url);
        URL url = new URL(target.toString());
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setDoOutput(true);
        OutputStream os = connection.getOutputStream();
        byte[] input = content.getBytes(StandardCharsets.UTF_8);
        os.write(input,0,input.length);
        connection.setConnectTimeout(2000);
        connection.setReadTimeout(2000);
        connection.connect();
        StringBuilder text = new StringBuilder();
        int responseCode = connection.getResponseCode();
        boolean error = false;
        InputStreamReader in;
        if (responseCode == HttpURLConnection.HTTP_OK ||
                responseCode == HttpURLConnection.HTTP_ACCEPTED ||
                responseCode == HttpURLConnection.HTTP_CREATED) {
            in = new InputStreamReader(connection.getInputStream());
        } else {
            in = new InputStreamReader(connection.getErrorStream());
        }
        BufferedReader buff = new BufferedReader(in);
        String line = buff.readLine();
        while (line != null) {
            text.append(line).append("\r\n");
            line = buff.readLine();
        }
        if(error)
            return "{\"M\":{\"status\":2,\"message\":\"" + text.toString() + "\"}}";

        Map<String,String> receive = new Gson().fromJson(text.toString(),new TypeToken<Map<String,String>>(){}.getType());
        String Kc = new String(SecurityFunctions.decryptAsymmetric(privateKey,decoder.decode(receive.get("K"))),"UTF-8");
        PublicKey Kcpub = SecurityFunctions.getPublicKey(Kc);
        String M = receive.get("M");
        String T1 = new String(SecurityFunctions.decryptAsymmetric(privateKey,decoder.decode(receive.get("T"))) ,"UTF-8");
        int authtime = ByteBuffer.wrap(T1.getBytes()).order(ByteOrder.LITTLE_ENDIAN).getInt();
        if(authtime == time2 + 1){
            //需要用Kcpub加密
            int tem = ByteBuffer.wrap(time1.getBytes()).order(ByteOrder.LITTLE_ENDIAN).getInt();
            String time_1 = new String((SecurityFunctions.encryptAsymmetric(Kcpub,
                    ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(tem).array())),"UTF-8");
            //String time_1 = new String(SecurityFunctions.encryptAsymmetric(Kcpub,String.valueOf(Long.parseLong(time1) + 1).getBytes()),"UTF-8") ;
            String T_1 = Base64.getEncoder().encodeToString(time_1.getBytes());
            return "{\"M\":" + M + ",\"T\":\"" + T_1 + "\"}";
        }
        return "\"M\":{\"status\":1,\"message\":\"time authentiaction failed\"";
    }

    /**
     * @Param data {"EToken": "Base64 encoded Kt public key encrypted (Token,nonce+1)",
     *              "M": "Base64 encoded Kt public key encrypted message",
     *              "T": "Base64 encoded Ks public key encrypted time1"}
     * @return
     * {"T": "Base64 encoded Kc public key encrypted token",
     *  "M": {"status": (number 0,1,2),"message": "status description"}
     *  "payload": "Base64 encoded Kc public key encrypted data"}
     */
    public String confirmLogin(String body) throws Exception{
        Base64.Decoder decoder = Base64.getDecoder();
        Map<String,String> bodydata = new Gson().fromJson(body,new TypeToken<Map<String,String>>(){}.getType());
        String EToken = bodydata.get("EToken");
        String M = bodydata.get("M");
        String time1 = new String(SecurityFunctions.decryptAsymmetric(privateKey,decoder.decode(bodydata.get("T").getBytes())),"UTF-8");
        int time2 = SecurityFunctions.generateRandom();
        String time = new String(SecurityFunctions.encryptAsymmetric(TpublicKey,ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(time2).array()),"UTF-8");
        String sysid = Base64.getEncoder().encodeToString(systemid.getBytes());

        String content = "{\"M\":\"" + M + "\",\"EToken\":\"" + EToken + "\",\"systemid\":\"" + sysid + "\"," +
                "\"T\":\"" + Base64.getEncoder().encodeToString(time.getBytes()) + "\"}";
        String target_url = "/qr/query";
        StringBuilder target = new StringBuilder(target_url);
        URL url = new URL(target.toString());
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setDoOutput(true);
        OutputStream os = connection.getOutputStream();
        byte[] input = content.getBytes(StandardCharsets.UTF_8);
        os.write(input,0,input.length);
        connection.setConnectTimeout(2000);
        connection.setReadTimeout(2000);
        connection.connect();
        StringBuilder text = new StringBuilder();
        int responseCode = connection.getResponseCode();
        boolean error = false;
        InputStreamReader in;
        if (responseCode == HttpURLConnection.HTTP_OK ||
                responseCode == HttpURLConnection.HTTP_ACCEPTED ||
                responseCode == HttpURLConnection.HTTP_CREATED) {
            in = new InputStreamReader(connection.getInputStream());
        } else {
            in = new InputStreamReader(connection.getErrorStream());
        }
        BufferedReader buff = new BufferedReader(in);
        String line = buff.readLine();
        while (line != null) {
            text.append(line).append("\r\n");
            line = buff.readLine();
        }
        if(error)
            return "{\"M\":{\"status\":2,\"message\":\"" + text.toString() + "\"}}";

        Map<String,String> receive = new Gson().fromJson(text.toString(),new TypeToken<Map<String,String>>(){}.getType());
        String Kc = new String(SecurityFunctions.decryptAsymmetric(privateKey,decoder.decode(receive.get("K"))),"UTF-8");
        PublicKey Kcpub = SecurityFunctions.getPublicKey(Kc);
        String message = receive.get("M");
        int tem = ByteBuffer.wrap(time1.getBytes()).order(ByteOrder.LITTLE_ENDIAN).getInt();
        String time_1 = new String((SecurityFunctions.encryptAsymmetric(Kcpub,
                ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(tem).array())),"UTF-8");
        //需要用Kcpub加密
        //String time_1 = new String(SecurityFunctions.encryptAsymmetric(publicKey,String.valueOf(Long.parseLong(time1) + 1).getBytes()),"UTF-8") ;
        String T_1 = Base64.getEncoder().encodeToString(time_1.getBytes());
        return "{\"M\":" + message + ",\"T\":\"" + T_1 + "\"}";

    }
}
