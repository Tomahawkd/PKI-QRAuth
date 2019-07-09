package io.tomahawkd.pki.api.server;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;
import io.tomahawkd.pki.api.server.util.*;
import io.tomahawkd.pki.api.server.util.SecurityFunctions;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class Token {
    private static PublicKey publicKey;
    private static PrivateKey privateKey;
    private static PublicKey TpublicKey;
    private String Kcs;
    private static String systemid;

    private static final String IP = "http://39.106.80.38";
    private static Token instance;

    public static Token getInstance() {
        if (instance == null) instance = new Token();
        return instance;
    }

    public static void setApiKey(String api) {
        systemid = api;
    }

   /* private Token() {
        try {
            TpublicKey = SecurityFunctions.readPublicKey(this.getTPublicKey());
        } catch (Exception e) {
        }

    }*/

    public static void readPublicKey(byte[] pub) throws IOException {
        publicKey = SecurityFunctions.readPublicKey(pub);
    }

    public static void readTPublicKey() throws Exception {
        TpublicKey = SecurityFunctions.readPublicKey(Base64.getDecoder().decode(getTPublicKey()));
    }

    public static void readPrivateKey(byte[] pri) throws IOException {
        privateKey = SecurityFunctions.readPrivateKey(pri);
    }


    public String TPublicKeyDistribute() throws Exception {
        Base64.Encoder encoder = Base64.getEncoder();
        return encoder.encodeToString(TpublicKey.getEncoded());

    }

    public String SpublicKeyDistribute() throws Exception {
        Base64.Encoder encoder = Base64.getEncoder();
        if (publicKey == null)
            return "public key is null";
        return encoder.encodeToString(publicKey.getEncoded());
    }

    /**
     * @return {"EToken": "Base64 encoded Kc public key encrypted token",
     * "M": {"status": (number 0,1,2),"message": "status description"},
     * "KP": "Base64 encoded Kc,t encrypted (Kc public key,Kc private key)",
     * "T": "Base64 encoded Kc public key encrypted (time1+1)"}
     * @Param data {"payload": "Base64 encoded Ks public key encrypted (username,password)",
     * * "S": "Base64 encoded Ks public key encrypted (Kc,s,time1)",
     * * "K": "Base64 encoded Kt public key encrypted Kc,t",
     * * "iv": "Base64 encoded Kt public key encrypted iv"}
     */
    public String acceptInitializeAuthenticationMessage(String body, String ip, String device, ThrowableFunction<String, Message<String>> callback, OnError onerror) throws Exception {
        Map<String, String> bodyData =
                new Gson().fromJson(body, new TypeToken<Map<String, String>>() {
                }.getType());
        Base64.Decoder decoder = Base64.getDecoder();
        String payload = bodyData.get("payload");

        Message<String> userMessage = callback.apply(payload);
        if (userMessage.getStatus() == -1)  //用户已存在
            return userMessage.toJson();
//todo time1
        int time1 = ByteBuffer.wrap(
                SecurityFunctions.decryptAsymmetric(privateKey, Utils.base64Decode(bodyData.get("T"))))
                .order(ByteOrder.LITTLE_ENDIAN).getInt() + 1;

        int t = SecurityFunctions.generateRandom();
        String time2 = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(TpublicKey,
                ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(t).array()));
        int userid = userMessage.getStatus();     //userid获得
        System.out.println(userid + "");
        //加密payload userid和systemid
        String idc = userid + ";" + systemid;
        String eidc = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(TpublicKey, idc.getBytes()));
        String D = ip + ";" + device;
        Map<String, String> requestMap = new HashMap<>();
        requestMap.put("K", bodyData.get("K"));
        requestMap.put("iv", bodyData.get("iv"));
        requestMap.put("id", eidc);
        requestMap.put("D", D);
        requestMap.put("T", time2);
        //encode K,idc,time2

        try {
            String target_url = IP + "/token/init";
            URL url = new URL(target_url);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            System.out.println("1");
            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "application/json");
            System.out.println("2");

            String content = new Gson().toJson(requestMap);
            OutputStream os = connection.getOutputStream();
            System.out.println(content);

            byte[] input = content.getBytes(StandardCharsets.UTF_8);


            os.write(input);
            System.out.println("4");

            connection.setConnectTimeout(2000);
            connection.setReadTimeout(2000);
            connection.connect();
            System.out.println("5");
            boolean error = false;
            int responseCode = connection.getResponseCode();

            StringBuilder text = new StringBuilder();
            InputStreamReader in;
            System.out.println("6");

            //todo:failed
            if (responseCode == HttpURLConnection.HTTP_OK ||
                    responseCode == HttpURLConnection.HTTP_ACCEPTED ||
                    responseCode == HttpURLConnection.HTTP_CREATED) {
                in = new InputStreamReader(connection.getInputStream());
            } else {
                in = new InputStreamReader(connection.getErrorStream());
                error = true;
            }
            BufferedReader buff = new BufferedReader(in);
            String line = buff.readLine();
            while (line != null) {
                text.append(line);
                line = buff.readLine();
            }
            if (error) {
                System.out.println(text.toString());
                throw new Exception(text.toString());
            }

            Map<String, String> result =
                    new Gson().fromJson(text.toString(), new TypeToken<Map<String, String>>() {
                    }.getType());

            Message<String> message = new Gson().fromJson(result.get("M"),
                    new TypeToken<Message<String>>() {
            }.getType());
            int t1 = ByteBuffer.wrap(
                    SecurityFunctions.decryptAsymmetric(privateKey,
                            decoder.decode(result.get("T"))))
                    .order(ByteOrder.LITTLE_ENDIAN).getInt();

            if (t1 == t + 1 && message.isOk()) {
                byte[] k = Utils.base64Decode(result.get("K"));
                PublicKey Kcpub = SecurityFunctions.readPublicKey(k);
                //todo time
                String time = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(Kcpub,
                        ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).
                                putInt(time1).array()));

                Map<String, String> responseMap = new HashMap<>();
                responseMap.put("EToken", result.get("EToken"));
                responseMap.put("KP", result.get("KP"));
                responseMap.put("T", time);
                responseMap.put("M", new Message<String>().setOK().setMessage("success").toJson());
                System.out.println("success");
                return new Gson().toJson(responseMap);
            } else
                throw new Exception();
        } catch (IOException e) {
            System.out.println("delete");
            onerror.delete(userid);
            e.printStackTrace();
            return "{\"M\":{\"status\":2,\"message\":\"failed\"}}";

        } catch (JsonSyntaxException e) {
            e.printStackTrace();
            throw new MalformedJsonException("Json parse error");
        } catch (CipherErrorException e) {
            e.printStackTrace();
            return "CipherErrorException";
        }
    }

    /**
     * @return {"T": "Base64 encoded Kc public key encrypted token",
     * "M": {
     * "status": (number 0,1,2),"message":
     * "status description"
     * }
     * "payload": "Base64 encoded Kc public key encrypted data"}
     * @Param data {"payload": "Base64 encoded data",
     * * "EToken": "Base64 encoded Kt public key encrypted (token,nonce+1)",
     * * payload
     * * "T": "Base64 encoded Ks public key encrypted time1"}
     */
    public String authentication(String body, String ip, String device, ReturnDataFunction<String, String> callback) throws Exception {
        Map<String, String> bodydata = new Gson().fromJson(body, new TypeToken<Map<String, String>>() {
        }.getType());
        Base64.Decoder decoder = Base64.getDecoder();
        String payload = new String(decoder.decode(bodydata.get("payload")), StandardCharsets.UTF_8);
        String etoken = bodydata.get("EToken");
        String T = bodydata.get("T");
        String time1 = new String(SecurityFunctions.decryptAsymmetric(privateKey, T.getBytes()), StandardCharsets.UTF_8);
        int t = SecurityFunctions.generateRandom();
        String time2 = new String((SecurityFunctions.encryptAsymmetric(TpublicKey,
                ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(t).array())), StandardCharsets.UTF_8);

        String d = ip + ";" + device;

        String target_url = IP + "/token/validate";
        StringBuilder target = new StringBuilder(target_url);
        URL url = new URL(target.toString());
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setDoOutput(true);
        TokenRequestMessage<String> tokenRequestMessage = new TokenRequestMessage<String>();
        tokenRequestMessage.setDevice(d);
        tokenRequestMessage.setTime(Base64.getEncoder().encodeToString(time2.getBytes()));
        tokenRequestMessage.setToken(etoken);
        OutputStream os = connection.getOutputStream();
        byte[] input = tokenRequestMessage.toJson().getBytes(StandardCharsets.UTF_8);
        os.write(input, 0, input.length);
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
            error = true;
        }
        BufferedReader buff = new BufferedReader(in);
        String line = buff.readLine();
        while (line != null) {
            text.append(line);
            line = buff.readLine();
        }
        text.delete(text.length() - 2, text.length() - 1);
        if (error)
            return "{\"M\":{\"status\":2,\"message\":\"" + text.toString() + "\"}}";

        String ereceive = text.toString();
        Map<String, String> receive = new Gson().fromJson(ereceive, new TypeToken<Map<String, String>>() {
        }.getType());
        String M = receive.get("M");
        Map<String, String> message = new Gson().fromJson(M, new TypeToken<Map<String, Integer>>() {
        }.getType());
        String K = new String(decoder.decode(receive.get("K")), StandardCharsets.UTF_8);
        String T2 = new String(SecurityFunctions.decryptAsymmetric(privateKey, decoder.decode(receive.get("T"))), StandardCharsets.UTF_8);
        int t1 = ByteBuffer.wrap(T2.getBytes()).order(ByteOrder.LITTLE_ENDIAN).getInt();
        PublicKey Kcpub = SecurityFunctions.readPublicKey(K);
        if (Integer.parseInt(message.get("status")) == 0 && t1 == t + 1) {
            String data = callback.apply(payload);
            int tem = ByteBuffer.wrap(time1.getBytes()).order(ByteOrder.LITTLE_ENDIAN).getInt() + 1;
            String time = new String((SecurityFunctions.encryptAsymmetric(Kcpub,
                    ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(tem).array())), StandardCharsets.UTF_8);
            //String time = new String(SecurityFunctions.encryptAsymmetric(Kcpub,String.valueOf(Long.parseLong(time1) + 1).getBytes()),StandardCharsets.UTF_8);
            Base64.Encoder encoder = Base64.getEncoder();
            String Payload = encoder.encodeToString(data.getBytes());
            return "{\"M\":{\"status\":0,\"message\":authentication success\"},\"T\":\"" + encoder.encodeToString(time.getBytes()) + "\",\"payload\":\"" + Payload + "\"}";
        }
        return "{\"M\":{\"status\":1,\"message\":time authentiaction failed\"}";
    }

    /**
     * @param { "K": "Base64 encoded Kt public key encrypted Kct"
     *          "iv": "Base64 encoded Kt public key encrypted iv"
     *          }
     * @return {
     * "nonce2": "Base64 encoded Kc encrypted nonce2"
     * "M": {"status": 0:success,1:time authentication failed,2:other error,
     * "message": "description"}
     * }
     */
    public String qrgenerate(String body) throws Exception {
        Map<String, String> map = new Gson().fromJson(body, new TypeToken<Map<String, String>>() {
        }.getType());
        String Kct = map.get("K");
        String iv = map.get("iv");
        int time2 = SecurityFunctions.generateRandom();
        String systemid = "";       //写死的
        String T = new String((SecurityFunctions.encryptAsymmetric(TpublicKey,
                ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(time2).array())), StandardCharsets.UTF_8);

        String content = "{\"K\":\"" + Kct + "\",\"iv\":\"" + iv + "\",\"T\":\"" + Base64.getEncoder().encodeToString(T.getBytes())
                + "\",\"systemid\":\"" + systemid + "\"}";
        Map<String, Object> result = request(content, IP + "/qr/genqr");
        if ((boolean) result.get("status"))
            return "{\"M\":{\"status\":2,\"message\":\"" + result.get("message") + "\"}}";

        String chat = new String(SecurityFunctions.decryptAsymmetric(privateKey, Base64.getDecoder().decode((String) result.get("T"))), StandardCharsets.UTF_8);
        int t = ByteBuffer.wrap(chat.getBytes()).order(ByteOrder.LITTLE_ENDIAN).getInt();
        if (t != time2 + 1)
            return "\"M\":{\"status\":1,\"message\":\"time authentication failed\"}";
        Map<String, String> M = new Gson().fromJson((String) result.get("M"), new TypeToken<Map<String, String>>() {
        }.getType());
        if (Integer.valueOf(M.get("status")) == 1)
            return "\"M\":{\"status\":2,\"message\":\"" + M.get("message") + "\"}";
        return "{\"nonce2\":\"" + result.get("nonce2") + "\",\"M\":{\"status\":0,\"message\":\""
                + (String) M.get("message") + "\"}}";
    }


    /**
     * @param { "EToken": "Base64 encoded Kt public key encrypted token,nonce+1(by client)",
     *          "T": "Base64 encoded Ks public key encrypted challenge number",
     *          M:{
     *          status: 1  2
     *          N:
     *          }
     * @return {
     * "M": "
     * {
     * "status": number(0:valid, 1:,2),
     * "message": ""
     * }",
     * "T": "Base64 encoded Kc public key encrypted challenge number + 1",
     * }
     */
    public String qroperation(String body, String ip, String device) throws Exception {
        Base64.Decoder decoder = Base64.getDecoder();
        Base64.Encoder encoder = Base64.getEncoder();
        Map<String, String> bodydata = new Gson().fromJson(body, new TypeToken<Map<String, String>>() {
        }.getType());
        String EToken = bodydata.get("EToken");
        Map<String, Object> M = new Gson().fromJson(bodydata.get("M"), new TypeToken<Map<String, Object>>() {
        }.getType());
        String time1 = new String(SecurityFunctions.decryptAsymmetric(privateKey, decoder.decode(bodydata.get("T").getBytes())), StandardCharsets.UTF_8);
        int tem = ByteBuffer.wrap(time1.getBytes()).order(ByteOrder.LITTLE_ENDIAN).getInt();
        int time2 = SecurityFunctions.generateRandom();
        String time = new String(SecurityFunctions.encryptAsymmetric(TpublicKey, ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(time2).array()), StandardCharsets.UTF_8);
        String sysid = Base64.getEncoder().encodeToString(systemid.getBytes());

        String d = ip + ";" + device;

        Map<String, Object> result = null;
        if ((int) M.get("status") == 1) {      //scan
            String N = (String) M.get("message");
            TokenRequestMessage<String> tokenRequestMessage = new TokenRequestMessage<String>();
            tokenRequestMessage.setToken(EToken);
            tokenRequestMessage.setDevice(d);
            tokenRequestMessage.setTime(Base64.getEncoder().encodeToString(time.getBytes()));
            tokenRequestMessage.setMessage(new Message(1, N));

            result = request(tokenRequestMessage.toJson(), IP + "/qr/update");
        } else {        //confirm
            String N = (String) M.get("message");
            TokenRequestMessage<String> tokenRequestMessage = new TokenRequestMessage<String>();
            tokenRequestMessage.setToken(EToken);
            tokenRequestMessage.setDevice(d);
            tokenRequestMessage.setTime(Base64.getEncoder().encodeToString(time.getBytes()));
            tokenRequestMessage.setMessage(new Message(2, N));
            result = request(tokenRequestMessage.toJson(), IP + "/qr/update");
        }

        if ((boolean) result.get("status"))
            return "{\"M\":{\"status\":2,\"message\":\"" + result.get("message") + "\"}}";

        Map<String, String> receive = new Gson().fromJson((String) result.get("message"), new TypeToken<Map<String, String>>() {
        }.getType());

        if ((int) M.get("status") == 1) {      //scan
            String Kc = new String(SecurityFunctions.decryptAsymmetric(privateKey, decoder.decode(receive.get("K"))), "UTF-8");
            PublicKey Kcpub = SecurityFunctions.readPublicKey(Kc);
            String m = receive.get("M");
            Map<String, Object> mes = new Gson().fromJson(m, new TypeToken<Map<String, Object>>() {
            }.getType());
            if ((int) mes.get("status") == 1)
                return "\"M\":{\"status\":2,\"message\":\"" + mes.get("message") + "\"}";
            String T1 = new String(SecurityFunctions.decryptAsymmetric(privateKey, decoder.decode(receive.get("T"))), "UTF-8");
            int authtime = ByteBuffer.wrap(T1.getBytes()).order(ByteOrder.LITTLE_ENDIAN).getInt();

            if (authtime == time2 + 1) {
                String time_1 = new String((SecurityFunctions.encryptAsymmetric(Kcpub,
                        ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(tem + 1).array())), "UTF-8");
                String T_1 = encoder.encodeToString(time_1.getBytes());
                return "{\"M\":{\"status\":0,\"message\":\"" + mes.get("message") + "\"},\"T\":\"" + T_1 + "\"}";
            }
            return "\"M\":{\"status\":1,\"message\":\"time authentiaction failed\"}";
        } else {
            String Kc = new String(SecurityFunctions.decryptAsymmetric(privateKey, decoder.decode(receive.get("K"))), "UTF-8");
            PublicKey Kcpub = SecurityFunctions.readPublicKey(Kc);
            String m = receive.get("M");
            Map<String, Object> jm = new Gson().fromJson(m, new TypeToken<Map<String, Object>>() {
            }.getType());
            if ((int) jm.get("status") == 1)
                return "{\"M\":{\"status\":2,\"message\":\"" + jm.get("message") + "\"}}";
            String message = (String) jm.get("message");

            String time_1 = new String((SecurityFunctions.encryptAsymmetric(Kcpub,
                    ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(tem + 1).array())), "UTF-8");
            String T_1 = encoder.encodeToString(time_1.getBytes());
            return "{\"M\":{\"status\":0,\"message\":\"" + message + "\"},\"T\":\"" + T_1 + "\"}";
        }
    }

    /**
     * -
     *
     * @return M:{type: -1 not exists 0 not scanned 1 scanned 2 confimed} if type==2  EToken :  KP:
     * if type==2  EToken  KP
     * @Param nonce2
     */
    public String rolling(String body, String ip, String device) throws Exception {
        Base64.Decoder decoder = Base64.getDecoder();
        Map<String, String> bodydata = new Gson().fromJson(body, new TypeToken<Map<String, String>>() {
        }.getType());
        String nonce2 = bodydata.get("nonce2");

        String d = ip + ";" + device;
        int time2 = SecurityFunctions.generateRandom();
        String time = new String(SecurityFunctions.encryptAsymmetric(TpublicKey, ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(time2).array()), StandardCharsets.UTF_8);
        String sysid = Base64.getEncoder().encodeToString(systemid.getBytes());

        String content = "{\"nonce2\":\"" + nonce2 + "\"," + "\"system\":\"" + sysid + "\"" +
                "\"T\":\"" + Base64.getEncoder().encodeToString(time.getBytes()) +
                "\",\"D\":\"" + d + "\"}";
        String target_url = IP + "/qr/query";
        StringBuilder target = new StringBuilder(target_url);
        URL url = new URL(target.toString());
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setDoOutput(true);
        OutputStream os = connection.getOutputStream();
        byte[] input = content.getBytes(StandardCharsets.UTF_8);
        os.write(input, 0, input.length);
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
            error = true;
        }
        BufferedReader buff = new BufferedReader(in);
        String line = buff.readLine();
        while (line != null) {
            text.append(line);
            line = buff.readLine();
        }
        text.delete(text.length() - 2, text.length() - 1);
        if (error)
            return "{\"M\":{\"status\":2,\"message\":\"" + text.toString() + "\"}}";
        Map<String, String> receive = new Gson().fromJson(text.toString(), new TypeToken<Map<String, String>>() {
        }.getType());
        String T1 = new String(SecurityFunctions.decryptAsymmetric(privateKey, decoder.decode(receive.get("T"))), StandardCharsets.UTF_8);
        int authtime = ByteBuffer.wrap(T1.getBytes()).order(ByteOrder.LITTLE_ENDIAN).getInt();
        if (authtime == time2 + 1) {
            String m = receive.get("M");
            Map<String, Object> tm = new Gson().fromJson(m, new TypeToken<Map<String, Object>>() {
            }.getType());
            int type = (int) (tm.get("type"));
            if (type == 2) {
                String etoken = receive.get("EToken");
                String kp = receive.get("KP");
                return "{\"M\":\"" + m + "\"" + "\"EToken\":\"" + etoken + "\"" + "\"KP\":\"" + kp + "\"}";
            } else
                return "{\"M\":\"" + m + "\"}";
        } else
            return "{\"M\":{\"status\":1,\"message\":\"time authentiaction failed\"}}";
    }

    /**
     * @param { "EToken": "Base64 encoded Kt public key encrypted token,nonce+1(by client)",
     *          "T": "Base64 encoded Ks public key encrypted challenge number",
     *          <p>
     *          }
     * @return {
     * "
     * "M": "
     * {
     * "status": number(0:valid, 1:invalid,2:error),
     * "message": ""
     * }",
     * "T": "Base64 encoded Kc public key encrypted challenge number + 1",
     * <p>
     * }
     */
    public String userLogManagement(String body, String ip, String device) throws Exception {
        Base64.Decoder decoder = Base64.getDecoder();
        Map<String, String> bodydata = new Gson().fromJson(body, new TypeToken<Map<String, String>>() {
        }.getType());
        String etoken = bodydata.get("EToken");
        String time1 = new String(SecurityFunctions.decryptAsymmetric(privateKey, decoder.decode(bodydata.get("T").getBytes())), StandardCharsets.UTF_8);
        int time2 = SecurityFunctions.generateRandom();
        String time = new String(SecurityFunctions.encryptAsymmetric(TpublicKey, ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(time2).array()), StandardCharsets.UTF_8);

        String d = ip + ";" + device;
        TokenRequestMessage<String> tokenRequestMessage = new TokenRequestMessage<String>();
        tokenRequestMessage.setToken(etoken);
        tokenRequestMessage.setDevice(d);
        tokenRequestMessage.setTime(time);

        String target_url = IP + "/user/log";
        StringBuilder target = new StringBuilder(target_url);
        URL url = new URL(target.toString());
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setDoOutput(true);
        OutputStream os = connection.getOutputStream();
        byte[] input = tokenRequestMessage.toJson().getBytes(StandardCharsets.UTF_8);
        os.write(input, 0, input.length);
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
            error = true;
        }
        BufferedReader buff = new BufferedReader(in);
        String line = buff.readLine();
        while (line != null) {
            text.append(line);
            line = buff.readLine();
        }
        text.delete(text.length() - 2, text.length() - 1);
        if (error)
            return "{\"M\":{\"status\":2,\"message\":\"" + text.toString() + "\"}}";
        Map<String, String> receive = new Gson().fromJson(text.toString(), new TypeToken<Map<String, String>>() {
        }.getType());
        String T1 = new String(SecurityFunctions.decryptAsymmetric(privateKey, decoder.decode(receive.get("T"))), StandardCharsets.UTF_8);
        int authtime = ByteBuffer.wrap(T1.getBytes()).order(ByteOrder.LITTLE_ENDIAN).getInt();
        if (authtime == time2 + 1) {
            String Kc = new String(SecurityFunctions.decryptAsymmetric(privateKey, decoder.decode(receive.get("K"))), StandardCharsets.UTF_8);
            PublicKey Kcpub = SecurityFunctions.readPublicKey(Kc);
            String m = receive.get("M");
            int tem = ByteBuffer.wrap(time1.getBytes()).order(ByteOrder.LITTLE_ENDIAN).getInt() + 1;
            String time_1 = new String((SecurityFunctions.encryptAsymmetric(Kcpub,
                    ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(tem).array())), StandardCharsets.UTF_8);
            String T_1 = Base64.getEncoder().encodeToString(time_1.getBytes());
            return "{\"M\":\"" + m + "\",\"T\":\"" + T_1 + "\"}";
        } else
            return "\"M\":{\"status\":1,\"message\":\"time authentiaction failed\"}";
    }

    /**
     * @param { "EToken": "Base64 encoded Kt public key encrypted token,nonce+1(by client)",
     *          "T": "Base64 encoded Ks public key encrypted challenge number",
     *          }
     * @return {
     * "M":
     * {
     * "status": number(0:valid, 1:invalid,2:error),
     * "message": ""
     * }",
     * "T": "Base64 encoded Kc public key encrypted challenge number + 1",
     * }
     */
    public String tokenListManagement(String body, String ip, String device) throws Exception {
        Base64.Decoder decoder = Base64.getDecoder();
        Map<String, String> bodydata = new Gson().fromJson(body, new TypeToken<Map<String, String>>() {
        }.getType());
        String etoken = bodydata.get("EToken");
        String time1 = new String(SecurityFunctions.decryptAsymmetric(privateKey, decoder.decode(bodydata.get("T").getBytes())), StandardCharsets.UTF_8);
        int time2 = SecurityFunctions.generateRandom();
        String time = new String(SecurityFunctions.encryptAsymmetric(TpublicKey, ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(time2).array()), StandardCharsets.UTF_8);

        String d = ip + ";" + device;
        TokenRequestMessage<String> tokenRequestMessage = new TokenRequestMessage<String>();
        tokenRequestMessage.setToken(etoken);
        tokenRequestMessage.setDevice(d);
        tokenRequestMessage.setTime(time);

        String target_url = IP + "/token/list";
        StringBuilder target = new StringBuilder(target_url);
        URL url = new URL(target.toString());
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setDoOutput(true);
        OutputStream os = connection.getOutputStream();
        byte[] input = tokenRequestMessage.toJson().getBytes(StandardCharsets.UTF_8);
        os.write(input, 0, input.length);
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
            error = true;
        }
        BufferedReader buff = new BufferedReader(in);
        String line = buff.readLine();
        while (line != null) {
            text.append(line);
            line = buff.readLine();
        }
        text.delete(text.length() - 2, text.length() - 1);
        if (error)
            return "{\"M\":{\"status\":2,\"message\":\"" + text.toString() + "\"}}";
        Map<String, String> receive = new Gson().fromJson(text.toString(), new TypeToken<Map<String, String>>() {
        }.getType());
        String T1 = new String(SecurityFunctions.decryptAsymmetric(privateKey, decoder.decode(receive.get("T"))), StandardCharsets.UTF_8);
        int authtime = ByteBuffer.wrap(T1.getBytes()).order(ByteOrder.LITTLE_ENDIAN).getInt();
        if (authtime == time2 + 1) {
            String Kc = new String(SecurityFunctions.decryptAsymmetric(privateKey, decoder.decode(receive.get("K"))), StandardCharsets.UTF_8);
            PublicKey Kcpub = SecurityFunctions.readPublicKey(Kc);
            String m = receive.get("M");
            int tem = ByteBuffer.wrap(time1.getBytes()).order(ByteOrder.LITTLE_ENDIAN).getInt() + 1;
            String time_1 = new String((SecurityFunctions.encryptAsymmetric(Kcpub,
                    ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(tem).array())), StandardCharsets.UTF_8);
            String T_1 = Base64.getEncoder().encodeToString(time_1.getBytes());
            return "{\"M\":\"" + m + "\",\"T\":\"" + T_1 + "\"}";
        } else
            return "\"M\":{\"status\":1,\"message\":\"time authentiaction failed\"}";
    }


    /**
     * @param { "EToken": "Base64 encoded Kt public key encrypted token,nonce+1(by client)",
     *          "T": "Base64 encoded Ks public key encrypted challenge number",
     *          "M": {
     *          "status": 0
     *          "message": "single token id to revoke"
     *          }
     *          }
     * @return {
     * "M": "
     * {
     * "status": number(0:valid, 1:invalid,2:error),
     * "message": "service message"
     * }",
     * "T": "Base64 encoded Kc public key encrypted challenge number + 1",
     * "
     * }
     */
    public String revokeToken(String body, String ip, String device) throws Exception {
        Base64.Decoder decoder = Base64.getDecoder();
        Map<String, String> bodydata = new Gson().fromJson(body, new TypeToken<Map<String, String>>() {
        }.getType());
        String etoken = bodydata.get("EToken");
        String m = bodydata.get("M");
        Map<String, String> cm = new Gson().fromJson(m, new TypeToken<Map<String, String>>() {
        }.getType());
        String time1 = new String(SecurityFunctions.decryptAsymmetric(privateKey, decoder.decode(bodydata.get("T").getBytes())), StandardCharsets.UTF_8);
        int time2 = SecurityFunctions.generateRandom();
        String time = new String(SecurityFunctions.encryptAsymmetric(TpublicKey, ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(time2).array()), StandardCharsets.UTF_8);

        String d = ip + ";" + device;
        TokenRequestMessage<String> tokenRequestMessage = new TokenRequestMessage<String>();
        tokenRequestMessage.setToken(etoken);
        tokenRequestMessage.setDevice(d);
        tokenRequestMessage.setTime(time);
        tokenRequestMessage.setMessage(new Message<String>(Integer.parseInt(cm.get("status")), cm.get("message")));

        String target_url = IP + "/token/revoke";
        StringBuilder target = new StringBuilder(target_url);
        URL url = new URL(target.toString());
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setDoOutput(true);
        OutputStream os = connection.getOutputStream();
        byte[] input = tokenRequestMessage.toJson().getBytes(StandardCharsets.UTF_8);
        os.write(input, 0, input.length);
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
            error = true;
        }
        BufferedReader buff = new BufferedReader(in);
        String line = buff.readLine();
        while (line != null) {
            text.append(line);
            line = buff.readLine();
        }
        text.delete(text.length() - 2, text.length() - 1);
        if (error)
            return "{\"M\":{\"status\":2,\"message\":\"" + text.toString() + "\"}}";

        Map<String, String> receive = new Gson().fromJson(text.toString(), new TypeToken<Map<String, String>>() {
        }.getType());
        String T1 = new String(SecurityFunctions.decryptAsymmetric(privateKey, decoder.decode(receive.get("T"))), StandardCharsets.UTF_8);
        int authtime = ByteBuffer.wrap(T1.getBytes()).order(ByteOrder.LITTLE_ENDIAN).getInt();
        if (authtime == time2 + 1) {
            String Kc = new String(SecurityFunctions.decryptAsymmetric(privateKey, decoder.decode(receive.get("K"))), StandardCharsets.UTF_8);
            PublicKey Kcpub = SecurityFunctions.readPublicKey(Kc);
            String M = receive.get("M");
            int tem = ByteBuffer.wrap(time1.getBytes()).order(ByteOrder.LITTLE_ENDIAN).getInt() + 1;
            String time_1 = new String((SecurityFunctions.encryptAsymmetric(Kcpub,
                    ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(tem).array())), StandardCharsets.UTF_8);
            String T_1 = Base64.getEncoder().encodeToString(time_1.getBytes());
            return "{\"M\":\"" + M + "\",\"T\":\"" + T_1 + "\"}";
        } else
            return "\"M\":{\"status\":1,\"message\":\"time authentiaction failed\"}";
    }

    /**
     * @param { "EToken": "Base64 encoded Kt public key encrypted token,nonce+1(by client)",
     *          "T": "Base64 encoded Ks public key encrypted challenge number",
     *          }
     * @return {
     * "M": "
     * {
     * "status": number(0:valid, 1:invalid),
     * "message": "service message"
     * }",
     * "T": "Base64 encoded Kc public key encrypted challenge number + 1",
     * }
     */
    public String regenerateKeys(String body, String ip, String device) throws Exception {
        Base64.Decoder decoder = Base64.getDecoder();
        Map<String, String> bodydata = new Gson().fromJson(body, new TypeToken<Map<String, String>>() {
        }.getType());
        String etoken = bodydata.get("EToken");
        String time1 = new String(SecurityFunctions.decryptAsymmetric(privateKey, decoder.decode(bodydata.get("T").getBytes())), StandardCharsets.UTF_8);
        int time2 = SecurityFunctions.generateRandom();
        String time = new String(SecurityFunctions.encryptAsymmetric(TpublicKey, ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(time2).array()), StandardCharsets.UTF_8);

        String d = ip + ";" + device;
        TokenRequestMessage<String> tokenRequestMessage = new TokenRequestMessage<String>();
        tokenRequestMessage.setToken(etoken);
        tokenRequestMessage.setDevice(d);
        tokenRequestMessage.setTime(time);

        String target_url = IP + "/keys/regen";
        StringBuilder target = new StringBuilder(target_url);
        URL url = new URL(target.toString());
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setDoOutput(true);
        OutputStream os = connection.getOutputStream();
        byte[] input = tokenRequestMessage.toJson().getBytes(StandardCharsets.UTF_8);
        os.write(input, 0, input.length);
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
            error = true;
        }
        BufferedReader buff = new BufferedReader(in);
        String line = buff.readLine();
        while (line != null) {
            text.append(line);
            line = buff.readLine();
        }
        text.delete(text.length() - 2, text.length() - 1);
        if (error)
            return "{\"M\":{\"status\":2,\"message\":\"" + text.toString() + "\"}}";

        Map<String, String> receive = new Gson().fromJson(text.toString(), new TypeToken<Map<String, String>>() {
        }.getType());
        String T1 = new String(SecurityFunctions.decryptAsymmetric(privateKey, decoder.decode(receive.get("T"))), StandardCharsets.UTF_8);
        int authtime = ByteBuffer.wrap(T1.getBytes()).order(ByteOrder.LITTLE_ENDIAN).getInt();
        if (authtime == time2 + 1) {
            String Kc = new String(SecurityFunctions.decryptAsymmetric(privateKey, decoder.decode(receive.get("K"))), StandardCharsets.UTF_8);
            PublicKey Kcpub = SecurityFunctions.readPublicKey(Kc);
            String M = receive.get("M");
            int tem = ByteBuffer.wrap(time1.getBytes()).order(ByteOrder.LITTLE_ENDIAN).getInt() + 1;
            String time_1 = new String((SecurityFunctions.encryptAsymmetric(Kcpub,
                    ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(tem).array())), StandardCharsets.UTF_8);
            String T_1 = Base64.getEncoder().encodeToString(time_1.getBytes());
            return "{\"M\":\"" + M + "\",\"T\":\"" + T_1 + "\"}";
        } else
            return "\"M\":{\"status\":1,\"message\":\"time authentiaction failed\"}";
    }

    public String deinit(String body, String ip, String device) throws Exception {
        Map<String, String> data = new Gson().fromJson(body, new TypeToken<Map<String, String>>() {
        }.getType());
        String EToken = data.get("EToken");
        int time = SecurityFunctions.generateRandom();
        String t = new String(SecurityFunctions.encryptAsymmetric(TpublicKey, ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(time).array()), StandardCharsets.UTF_8);
        String D = ip + ";" + device;

        String content = "{\"EToken\":\"" + EToken + "\",\"T\":\""
                + Base64.getEncoder().encodeToString(t.getBytes()) +
                "\",\"D\":\"" + D + "\"}";
        Map<String, Object> result = request(content, "/token/deinit");
        if ((boolean) result.get("status"))
            return "{\"M\":{\"status\":2,\"message\":\"" + result.get("message") + "\"}}";

        Map<String, String> receive = new Gson().fromJson((String) result.get("message"), new TypeToken<Map<String, String>>() {
        }.getType());
        String T1 = new String(SecurityFunctions.decryptAsymmetric(privateKey, Base64.getDecoder().decode(receive.get("T"))), StandardCharsets.UTF_8);
        int authtime = ByteBuffer.wrap(T1.getBytes()).order(ByteOrder.LITTLE_ENDIAN).getInt();
        if (authtime == time + 1) {
            String M = receive.get("M");
            Map<String, String> m = new Gson().fromJson(M, new TypeToken<Map<String, String>>() {
            }.getType());
            if (Integer.valueOf(m.get("status")) == 1)
                return "{\"M\":{\"status\":2,\"message\":\"" + m.get("message") + "\"}}";
            return "{\"M\":{\"status\":0,\"message\":\"" + m.get("message") + "\"}}";
        }
        return "{\"M\":{\"status\":1,\"message\":\"time authentiaction failed\"}}";
    }


    private static String getTPublicKey() throws Exception {
        //todo files not file
        File file = new File("./web/src/main/resources/tpublic.pub");
        if (!file.exists()) {       // 向服务器获取   并写入文件
            String target_url = IP + "/keys/auth";
            URL url = new URL(target_url);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
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
                error = true;
            }
            BufferedReader buff = new BufferedReader(in);
            String line = buff.readLine();
            while (line != null) {
                text.append(line);
                line = buff.readLine();
            }
            if (error)
                return "{\"M\":{\"status\":2,\"message\":\"public key accept failed\"}}";

            try {
                file.createNewFile();
                FileWriter writer = new FileWriter(file);
                System.out.println("    55  ");
                writer.write("");//清空原文件内容
                writer.write(text.toString());
                writer.flush();
                writer.close();
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            return text.toString();
        } else {  //从文件中读取出来并返回
            return FileUtil.readFile("./web/src/main/resources/tpublic.pub");

        }
    }

    private Map<String, Object> request(String content, String target_url) throws Exception {
        StringBuilder target = new StringBuilder(target_url);
        URL url = new URL(target.toString());
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setDoOutput(true);
        OutputStream os = connection.getOutputStream();
        byte[] input = content.getBytes(StandardCharsets.UTF_8);
        os.write(input, 0, input.length);
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
            error = true;
        }
        BufferedReader buff = new BufferedReader(in);
        String line = buff.readLine();
        while (line != null) {
            text.append(line);
            line = buff.readLine();
        }
        text.delete(text.length() - 2, text.length() - 1);
        Map<String, Object> map = new HashMap<>();
        map.put("status", error);
        map.put("message", text.toString());
        return map;
    }


}
