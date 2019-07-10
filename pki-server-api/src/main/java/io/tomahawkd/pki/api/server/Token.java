package io.tomahawkd.pki.api.server;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import io.tomahawkd.pki.api.server.util.SecurityFunctions;
import io.tomahawkd.pki.api.server.util.*;

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


    public static void readPublicKey(byte[] pub) {
        publicKey = SecurityFunctions.readPublicKey(pub);
    }

    public static void readTPublicKey() throws Exception {
        TpublicKey = SecurityFunctions.readPublicKey(Base64.getDecoder().decode(getTPublicKey()));
    }

    public static void readPrivateKey(byte[] pri) {
        privateKey = SecurityFunctions.readPrivateKey(pri);
    }


    public String TPublicKeyDistribute() {
        return Utils.base64Encode(TpublicKey.getEncoded());

    }

    public String SpublicKeyDistribute() {
        if (publicKey == null) return null;
        return Utils.base64Encode(publicKey.getEncoded());
    }

    /**
     * @return {"EToken": "Base64 encoded Kc public key encrypted token",
     * "M": {"status": (number 0,1,2),"message": "status description"},
     * "KP": "Base64 encoded Kc,t encrypted (Kc public key,Kc private key)",
     * "T": "Base64 encoded Kc public key encrypted (time1+1)"}
     * @param body {"payload": "Base64 encoded Ks public key encrypted (username,password)",
     * * * "S": "Base64 encoded Ks public key encrypted (Kc,s,time1)",
     * * * "K": "Base64 encoded Kt public key encrypted Kc,t",
     * * * "iv": "Base64 encoded Kt public key encrypted iv"}
     */
    public String acceptInitializeAuthenticationMessage(String body, String ip, String device,
                                                        ThrowableFunction<String, Message<String>> callback,
                                                        OnError onerror) throws Exception {
        Map<String, String> bodyData =
                new Gson().fromJson(body, new TypeToken<Map<String, String>>() {
                }.getType());

        String payload = bodyData.get("payload");
        Message<String> userMessage = callback.apply(payload);
        if (userMessage.getStatus() == -1)
            return new Gson().toJson(new HashMap<>().put("M",
                    new Message<String>().setStatus(-1).setMessage(" failed").toJson()));

        int t = SecurityFunctions.generateRandom();
        String time2 = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(TpublicKey,
                ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(t).array()));
        int userid = userMessage.getStatus();
        String idc = userid + ";" + systemid;
        String eidc = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(TpublicKey, idc.getBytes()));
        Map<String, String> requestMap = new HashMap<>();
        requestMap.put("K", bodyData.get("K"));
        requestMap.put("iv", bodyData.get("iv"));
        requestMap.put("id", eidc);
        requestMap.put("D", ip + ";" + device);
        requestMap.put("T", time2);

        Map<String, String> responseMap = new HashMap<>();

        try {
            String target_url = IP + "/token/init";

            Map<String, Object> ereceive = request(new Gson().toJson(requestMap), target_url);

            if ((boolean) ereceive.get("status")) {
                responseMap.put("M",
                        new Message<String>().setStatus(2).setMessage((String) ereceive.get("message")).toJson());
                return new Gson().toJson(responseMap);
            }
            Map<String, String> receive = new Gson().fromJson((String) ereceive.get("message"),
                    new TypeToken<Map<String, String>>() {
                    }.getType());

            Message<String> message = new Gson().fromJson(receive.get("M"),
                    new TypeToken<Message<String>>() {
                    }.getType());

            if (message.isOk()) {

                int t1 = ByteBuffer.wrap(
                        SecurityFunctions.decryptAsymmetric(privateKey,
                                Utils.base64Decode(receive.get("T"))))
                        .order(ByteOrder.LITTLE_ENDIAN).getInt();

                if (t1 == t + 1) {
                    byte[] k = Utils.base64Decode(receive.get("K"));
                    PublicKey Kcpub = SecurityFunctions.readPublicKey(k);

                    String time = Utils.responseChallenge(bodyData.get("T"), Kcpub);

                    responseMap.put("M", new Message<String>().setOK().setMessage("success").toJson());
                    responseMap.put("EToken", receive.get("EToken"));
                    responseMap.put("KP", receive.get("KP"));
                    responseMap.put("T", time);
                    return new Gson().toJson(responseMap);
                } else throw new Exception("Time authentication error");
            } else throw new Exception("Message status error");
        } catch (Exception e) {
            onerror.delete(userid);
            responseMap.put("M", new Message<String>().setStatus(1).setMessage("failed").toJson());
            e.printStackTrace();
            return new Gson().toJson(responseMap);
        }
    }

    /**
     * @return {"T": "Base64 encoded Kc public key encrypted token",
     * "M": {
     * "status": (number 0,1,2),"message":
     * "status description"
     * }
     * "payload": "Base64 encoded Kc public key encrypted data"}
     * @param body {"payload": "Base64 encoded data",
     * * "EToken": "Base64 encoded Kt public key encrypted (token,nonce+1)",
     * * payload
     * * "T": "Base64 encoded Ks public key encrypted time1"}
     */
    public String authentication(String body, String ip, String device,
                                 ReturnDataFunction<String,String, String> callback) throws Exception {
        Map<String, String> bodydata = new Gson().fromJson(body, new TypeToken<Map<String, String>>() {
        }.getType());

        int t = SecurityFunctions.generateRandom();
        String time2 = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(TpublicKey,
                ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(t).array()));

        TokenRequestMessage<String> tokenRequestMessage = new TokenRequestMessage<>();
        tokenRequestMessage.setDevice(ip + ";" + device);
        tokenRequestMessage.setTime(time2);
        tokenRequestMessage.setToken(bodydata.get("EToken"));

        String target_url = IP + "/token/validate";

        Map<String, String> responseMap = new HashMap<>();

        Map<String, Object> ereceive = request(new Gson().toJson(tokenRequestMessage), target_url);

        if ((boolean) ereceive.get("status")) {
            responseMap.put("M",
                    new Message<String>().setStatus(2).setMessage((String) ereceive.get("message")).toJson());
            return new Gson().toJson(responseMap);
        }
        Map<String, String> receive = new Gson().fromJson((String) ereceive.get("message"),
                new TypeToken<Map<String,String>>() {
                }.getType());

        Message<String> message = new Gson().fromJson(receive.get("M"), new TypeToken<Message<String>>() {
        }.getType());

        if (message.isOk()) {
            int t1 = ByteBuffer.wrap(
                    SecurityFunctions.decryptAsymmetric(privateKey, Utils.base64Decode(receive.get("T"))))
                    .order(ByteOrder.LITTLE_ENDIAN).getInt();

            if (t1 == t + 1) {

                byte[] K = Utils.base64Decode(receive.get("K"));
                PublicKey Kcpub = SecurityFunctions.readPublicKey(K);

                String userid = new String(SecurityFunctions.decryptAsymmetric(privateKey,
                        Utils.base64Decode(bodydata.get("U"))));

                String data = callback.apply(bodydata.get("payload"), userid);
                String time = Utils.responseChallenge(bodydata.get("T"), Kcpub);

                responseMap.put("M", new Message<String>().setOK().setMessage("authentication success").toJson());
                responseMap.put("T", time);
                responseMap.put("payload", data);
            } else {
                responseMap.put("M", new Message<String>().setStatus(2).setMessage("time auth failed").toJson());
            }
        } else {
            responseMap.put("M", new Message<String>().setStatus(2).setMessage("failed").toJson());
        }
        return new Gson().toJson(responseMap);

    }

    /**
     * @param body { "K": "Base64 encoded Kt public key encrypted Kct"
     *          "iv": "Base64 encoded Kt public key encrypted iv"
     *          }
     * @return {
     * "nonce2": "Base64 encoded Kc encrypted nonce2"
     * "M": {"status": 0:success,1:time authentication failed,2:other error,
     * "message": "description"}
     * }
     */
    public String qrgenerate(String body) throws Exception {
        Map<String, String> bodydata = new Gson().fromJson(body, new TypeToken<Map<String, String>>() {
        }.getType());

        int t = SecurityFunctions.generateRandom();
        String time2 = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(TpublicKey,
                ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(t).array()));

        Map<String, String> requestMap = new HashMap<>();
        requestMap.put("K", bodydata.get("K"));
        requestMap.put("iv", bodydata.get("iv"));
        requestMap.put("T", time2);
        requestMap.put("system", systemid);

        String content = new Gson().toJson(requestMap);
        Map<String, Object> result = request(content, IP + "/qr/genqr");
      
        Map<String, String> responseMap = new HashMap<>();

        if ((boolean) result.get("status")){
            responseMap.put("M",new Message<String>().setStatus(2).setMessage((String) result.get("message")).toJson());
            return new Gson().toJson(responseMap);
        }

        Map<String, String> eresult = new Gson().fromJson((String) result.get("message"),
                new TypeToken<Map<String, String>>() {
                }.getType());

        Message<String> message = new Gson().fromJson(eresult.get("M"), new TypeToken<Message<String>>() {
        }.getType());

        if (message.isError()){
            responseMap.put("M",new Message<String>().setStatus(1).setMessage(message.getMessage()).toJson());
            return new Gson().toJson(responseMap);
        }

        int t1 = ByteBuffer.wrap(SecurityFunctions.decryptAsymmetric(privateKey,
                Base64.getDecoder().decode(eresult.get("T")))).order(ByteOrder.LITTLE_ENDIAN).getInt();

        if (t1 != t + 1){
            responseMap.put("M",
                    new Message<String>().setStatus(1).setMessage("time authentication failed").toJson());
            return new Gson().toJson(responseMap);
        }

        responseMap.put("nonce2", eresult.get("nonce2"));
        responseMap.put("M", new Message<String>().setOK().setMessage(message.getMessage()).toJson());
        return new Gson().toJson(responseMap);
    }

    /**
     * @param body { "EToken": "Base64 encoded Kt public key encrypted token,nonce+1(by client)",
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
        Map<String, String> bodydata = new Gson().fromJson(body, new TypeToken<Map<String, String>>() {
        }.getType());

        int t = SecurityFunctions.generateRandom();
        String time2 = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(TpublicKey,
                ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(t).array()));

        Map<String, Object> result;
        TokenRequestMessage<String> tokenRequestMessage = new TokenRequestMessage<>();
        tokenRequestMessage.setToken(bodydata.get("EToken"));
        tokenRequestMessage.setDevice(ip + ";" + device);
        tokenRequestMessage.setTime(time2);
        tokenRequestMessage.setRawMessage(bodydata.get("M"));

        result = request(tokenRequestMessage.toJson(), IP + "/qr/update");
        Map<String, String> responseMap = new HashMap<>();

        if ((boolean) result.get("status")) {
            responseMap.put("M",
                    new Message<String>().setStatus(2).setMessage((String) result.get("message")).toJson());
            return new Gson().toJson(responseMap);
        }
        Map<String, String> receive = new Gson().fromJson((String) result.get("message"),
                new TypeToken<Map<String, String>>() {
                }.getType());

        Message<String> message = new Gson().fromJson(receive.get("M"), new TypeToken<Message<String>>() {
        }.getType());

        if (message.isOk()) {

            int t1 = ByteBuffer.wrap(SecurityFunctions.decryptAsymmetric(privateKey,
                    Utils.base64Decode(receive.get("T")))).order(ByteOrder.LITTLE_ENDIAN).getInt();

            if (t1 == t + 1) {

                byte[] K = Utils.base64Decode(receive.get("K"));
                PublicKey Kcpub = SecurityFunctions.readPublicKey(K);

                String time = Utils.responseChallenge(bodydata.get("T"), Kcpub);
                responseMap.put("T", time);
                responseMap.put("M", new Message<String>().setOK().setMessage(message.getMessage()).toJson());
                return new Gson().toJson(responseMap);
            }
            responseMap.put("M",
                    new Message<String>().setError().setMessage("Time authentication failed").toJson());
            return new Gson().toJson(responseMap);

        } else {
            responseMap.put("M",
                    new Message<String>().setError().setMessage(message.getMessage()).toJson());
            return new Gson().toJson(responseMap);
        }
    }

    /**
     * -
     *
     * @return M:{type: -1 not exists 0 not scanned 1 scanned 2 confimed} if type==2  EToken :  KP:
     * if type==2  EToken  KP
     * @param body nonce2
     */
    public String rolling(String body, String ip, String device) throws Exception {
        Map<String, String> bodydata = new Gson().fromJson(body, new TypeToken<Map<String, String>>() {
        }.getType());

        int t = SecurityFunctions.generateRandom();
        String time2 = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(TpublicKey,
                ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(t).array()));

        Map<String, String> requestMap = new HashMap<>();
        requestMap.put("nonce2", bodydata.get("nonce2"));
        requestMap.put("system", systemid);
        requestMap.put("T", time2);
        requestMap.put("D", ip + ";" + device);
        String content = new Gson().toJson(requestMap);
        String target_url = IP + "/qr/query";
        Map<String, String> responseMap = new HashMap<>();

        Map<String, Object> ereceive = request(content, target_url);

        if ((boolean) ereceive.get("status")) {
            responseMap.put("M",
                    new Message<String>().setStatus(2).setMessage((String) ereceive.get("message")).toJson());
            return new Gson().toJson(responseMap);
        }
        Map<String, String> receive = new Gson().fromJson((String) ereceive.get("message"),
                new TypeToken<Map<String, String>>() {
                }.getType());


        String timeString = receive.get("T");
        if (timeString == null || timeString.isEmpty()) {
            responseMap.put("M",
                    new Message<String>().setStatus(-2).setMessage("Time Authentication Failed").toJson());
            return new Gson().toJson(responseMap);
        }

        int t1 = ByteBuffer.wrap(
                SecurityFunctions.decryptAsymmetric(privateKey, Utils.base64Decode(receive.get("T"))))
                .order(ByteOrder.LITTLE_ENDIAN).getInt();

        if (t1 == t + 1) {

            Message<String> statusMessage = new Gson().fromJson(receive.get("M"),
                    new TypeToken<Message<String>>() {
                    }.getType());

            responseMap.put("M", receive.get("M"));
            if (statusMessage.getStatus() == 2) { // confirmed
                responseMap.put("KP", receive.get("KP"));
                responseMap.put("EToken", receive.get("EToken"));
            }

            return new Gson().toJson(responseMap);
        } else {
            responseMap.put("M",
                    new Message<String>().setStatus(-2).setMessage("Time Authentication Failed").toJson());
            return new Gson().toJson(responseMap);
        }
    }

    /**
     *
     */
    public String deinit(String body, String ip, String device, ThrowableFunction<String, Boolean> callback)
            throws Exception {
        Map<String, String> data = new Gson().fromJson(body, new TypeToken<Map<String, String>>() {
        }.getType());

        int t = SecurityFunctions.generateRandom();
        String time = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(TpublicKey,
                ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(t).array()));

        Map<String, String> requestMap = new HashMap<>();
        requestMap.put("EToken", data.get("EToken"));
        requestMap.put("T", time);
        requestMap.put("D", ip + ";" + device);
        String content = new Gson().toJson(requestMap);
        Map<String, String> responseMap = new HashMap<>();

        Map<String, Object> result = request(content, "/token/deinit");

        if ((boolean) result.get("status")) {
            responseMap.put("M",
                    new Message<String>().setStatus(2).setMessage((String) result.get("message")).toJson());
            return new Gson().toJson(responseMap);
        }

        Map<String, String> receive = new Gson().fromJson((String) result.get("message"),
                new TypeToken<Map<String, String>>() {
                }.getType());

        Message<String> message = new Gson().fromJson(receive.get("M"),
                new TypeToken<Message<String>>() {
                }.getType());

        if (message.isOk()) {

            int t1 = ByteBuffer.wrap(SecurityFunctions.decryptAsymmetric(privateKey,
                    Utils.base64Decode(receive.get("T")))).order(ByteOrder.LITTLE_ENDIAN).getInt();

            if (t1 == t + 1) {
                byte[] K = Utils.base64Decode(receive.get("K"));
                PublicKey Kcpub = SecurityFunctions.readPublicKey(K);

                responseMap.put("T", Utils.responseChallenge(data.get("T"), Kcpub));

                String userid = new String(SecurityFunctions.decryptAsymmetric(privateKey,
                        Utils.base64Decode(receive.get("U"))));

                if (callback.apply(userid)) {
                    responseMap.put("M", new Message<String>().setOK().setMessage(message.getMessage()).toJson());

                } else {
                    responseMap.put("M",
                            new Message<String>().setStatus(-2).setMessage(message.getMessage()).toJson());
                }
                return new Gson().toJson(responseMap);
            }
        }
        return "{\"M\":{\"status\":1,\"message\":\"time authentiaction failed\"}}";
    }

    /**
     * @param body { "EToken": "Base64 encoded Kt public key encrypted token,nonce+1(by client)",
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
        return TokenUtils.tokenResponse(IP + "/user/log", body, ip, device, TpublicKey, privateKey);
    }

    /**
     * @param body { "EToken": "Base64 encoded Kt public key encrypted token,nonce+1(by client)",
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
        return TokenUtils.tokenResponse(IP + "/token/list", body, ip, device, TpublicKey, privateKey);
    }


    /**
     * @param body { "EToken": "Base64 encoded Kt public key encrypted token,nonce+1(by client)",
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
        return TokenUtils.tokenResponse(IP + "/token/revoke", body, ip, device, TpublicKey, privateKey);
    }

    /**
     * @param body { "EToken": "Base64 encoded Kt public key encrypted token,nonce+1(by client)",
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
        return TokenUtils.tokenResponse(IP + "/keys/regen", body, ip, device, TpublicKey, privateKey);
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

    public static Map<String, Object> request(String content, String target_url) throws Exception {
        URL url = new URL(target_url);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/json");
        connection.setDoOutput(true);
        OutputStream os = connection.getOutputStream();
        byte[] input = content.getBytes(StandardCharsets.UTF_8);
        os.write(input);
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
        Map<String, Object> map = new HashMap<>();
        map.put("status", error);
        map.put("message", text.toString());
        return map;
    }
}
