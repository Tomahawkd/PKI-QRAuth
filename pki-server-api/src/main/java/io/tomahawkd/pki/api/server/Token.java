package io.tomahawkd.pki.api.server;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;
import io.tomahawkd.pki.api.server.util.*;
import io.tomahawkd.pki.api.server.util.SecurityFunctions;
import sun.misc.BASE64Decoder;

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
     * @Param data {"payload": "Base64 encoded Ks public key encrypted (username,password)",
     *      * * "S": "Base64 encoded Ks public key encrypted (Kc,s,time1)",
     *      * * "K": "Base64 encoded Kt public key encrypted Kc,t",
     *      * * "iv": "Base64 encoded Kt public key encrypted iv"}
     * @return {"EToken": "Base64 encoded Kc public key encrypted token",
     * "M": {"status": (number 0,1,2),"message": "status description"},
     * "KP": "Base64 encoded Kc,t encrypted (Kc public key,Kc private key)",
     * "T": "Base64 encoded Kc public key encrypted (time1+1)"}
     *
     */
    public String acceptInitializeAuthenticationMessage(String body, String ip, String device, ThrowableFunction<String, Message<String>> callback, OnError onerror) throws Exception {
        Map<String, String> bodyData =
                new Gson().fromJson(body, new TypeToken<Map<String, String>>() {
                }.getType());
        Base64.Decoder decoder = Base64.getDecoder();
      //  String payload = new String(SecurityFunctions.decryptAsymmetric(privateKey, decoder.decode(bodyData.get("payload"))));
       String payload = bodyData.get("payload");
        System.out.println(payload);
        Message<String> userMessage = callback.apply(payload);
        if (userMessage.getStatus() == -1)  //用户已存在
            return new Gson().toJson(new HashMap<>().put("M", new Message<String>().setStatus(-1).setMessage(" failed").toJson()));

        int t = SecurityFunctions.generateRandom();
        String time2 = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(TpublicKey,
                ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(t).array()));
        int userid = userMessage.getStatus();
        String idc = userid + ";" + systemid;
        String eidc = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(TpublicKey, idc.getBytes()));
        String D = ip + ";" + device;
        Map<String, String> requestMap = new HashMap<>();
        requestMap.put("K", bodyData.get("K"));
        requestMap.put("iv", bodyData.get("iv"));
        requestMap.put("id", eidc);
        requestMap.put("D", D);
        requestMap.put("T", time2);

        Map<String, String> responseMap = new HashMap<>();

        try {
            String target_url = IP + "/token/init";

            Map<String, Object> ereceive = request(new Gson().toJson(requestMap), target_url);
            System.out.println("requestMap:"+new Gson().toJson(requestMap));
            if ((boolean) ereceive.get("status")) {
                System.out.println("error");
                System.out.println(ereceive.get("message"));
                responseMap.put("M", new Message<String>().setStatus(2).setMessage((String) ereceive.get("message")).toJson());
                return new Gson().toJson(responseMap);
            }
            Map<String, String> receive = new Gson().fromJson((String) ereceive.get("message"), new TypeToken<Map<String, String>>() {
            }.getType());

            Message<String> message = new Gson().fromJson(receive.get("M"),
                    new TypeToken<Message<String>>() {
                    }.getType());
            System.out.println(message.toJson());
            int t1 = ByteBuffer.wrap(
                    SecurityFunctions.decryptAsymmetric(privateKey,
                            decoder.decode(receive.get("T"))))
                    .order(ByteOrder.LITTLE_ENDIAN).getInt();

            if (t1 == t + 1 && message.isOk()) {
                byte[] k = Utils.base64Decode(receive.get("K"));
                PublicKey Kcpub = SecurityFunctions.readPublicKey(k);

                String time = Utils.responseChallenge(bodyData.get("T"), Kcpub);

                responseMap.put("M", new Message<String>().setOK().setMessage("success").toJson());
                responseMap.put("EToken", receive.get("EToken"));
                responseMap.put("KP", receive.get("KP"));
                responseMap.put("T", time);
                System.out.println("return:"+new Gson().toJson(responseMap));
                System.out.println("success");
                return new Gson().toJson(responseMap);
            } else
                throw new Exception();
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
     * @Param data {"payload": "Base64 encoded data",
     * * "EToken": "Base64 encoded Kt public key encrypted (token,nonce+1)",
     * * payload
     * * "T": "Base64 encoded Ks public key encrypted time1"}
     */
    public String authentication(String body, String ip, String device, ReturnDataFunction<String, String> callback) throws Exception {
        Map<String, String> bodydata = new Gson().fromJson(body, new TypeToken<Map<String, String>>() {
        }.getType());
        Base64.Decoder decoder = Base64.getDecoder();
        String payload = bodydata.get("payload");
        String etoken = bodydata.get("EToken");
        int t = SecurityFunctions.generateRandom();
        String time2 = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(TpublicKey,
                ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(t).array()));
        String d = ip + ";" + device;

        TokenRequestMessage<String> tokenRequestMessage = new TokenRequestMessage<String>();
        tokenRequestMessage.setDevice(d);
        tokenRequestMessage.setTime(time2);
        tokenRequestMessage.setToken(etoken);

        String target_url = IP + "/token/validate";

        Map<String, String> responseMap = new HashMap<>();

        Map<String, Object> ereceive = request(new Gson().toJson(tokenRequestMessage), target_url);

        if ((boolean) ereceive.get("status")) {
            responseMap.put("M", new Message<String>().setStatus(2).setMessage((String) ereceive.get("message")).toJson());
            return new Gson().toJson(responseMap);
        }
        Map<String, String> receive = new Gson().fromJson((String) ereceive.get("message"), new TypeToken<Map<String, Integer>>() {
        }.getType());
        String M = receive.get("M");
        Map<String, String> message = new Gson().fromJson(M, new TypeToken<Map<String, Integer>>() {
        }.getType());
        byte[] K = Utils.base64Decode(receive.get("K"));
        PublicKey Kcpub = SecurityFunctions.readPublicKey(K);

        int t1 = ByteBuffer.wrap(
                SecurityFunctions.decryptAsymmetric(privateKey, decoder.decode(receive.get("T"))))
                .order(ByteOrder.LITTLE_ENDIAN).getInt();
        if (Integer.parseInt(message.get("status")) == 0 && t1 == t + 1) {
            String data = callback.apply(payload);
            String time = Utils.responseChallenge(bodydata.get("T"), Kcpub);
            Base64.Encoder encoder = Base64.getEncoder();
            //TODO
            String Payload = encoder.encodeToString(data.getBytes());

            responseMap.put("M", new Message<String>().setOK().setMessage("authentication success").toJson());
            responseMap.put("T", time);
            responseMap.put("payload", Payload);
        } else {
            responseMap.put("M", new Message<String>().setStatus(2).setMessage("failed").toJson());
        }
        return new Gson().toJson(responseMap);

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
        Map<String, String> bodydata = new Gson().fromJson(body, new TypeToken<Map<String, String>>() {
        }.getType());
        String Kct = bodydata.get("K");
        String iv = bodydata.get("iv");
        int t = SecurityFunctions.generateRandom();
        String time2 = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(TpublicKey,
                ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(t).array()));

        Map<String, String> requestMap = new HashMap<>();
        requestMap.put("K", Kct);
        requestMap.put("iv", iv);
        requestMap.put("T", time2);
        requestMap.put("system", systemid);

        String content = new Gson().toJson(requestMap);
        Map<String, Object> result = request(content, IP + "/qr/genqr");
        if ((boolean) result.get("status"))
            return new Gson().toJson(new HashMap<>().put("M", new Message<String>().setStatus(2).setMessage((String) result.get("message")).toJson()));

        Map<String, String> eresult = new Gson().fromJson((String) result.get("message"), new TypeToken<Map<String, String>>() {
        }.getType());
        int t1 = ByteBuffer.wrap(SecurityFunctions.decryptAsymmetric(privateKey, Base64.getDecoder().decode(eresult.get("T")))).order(ByteOrder.LITTLE_ENDIAN).getInt();
        if (t1 != t + 1)
            return new Gson().toJson(new HashMap<>().put("M", new Message<String>().setStatus(1).setMessage("time authentication failed").toJson()));
        Message<String> M = new Gson().fromJson(eresult.get("M"), new TypeToken<Message<String>>() {
        }.getType());
        if (M.getStatus() == 1)
            return new Gson().toJson(new HashMap<>().put("M", new Message<String>().setStatus(1).setMessage(M.getMessage()).toJson()));
        Map<String, String> responseMap = new HashMap<>();
        responseMap.put("nonce2", eresult.get("nonce2"));
        responseMap.put("M", new Message<String>().setOK().setMessage(M.getMessage()).toJson());
        return new Gson().toJson(responseMap);
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
        Map<String, String> bodydata = new Gson().fromJson(body, new TypeToken<Map<String, String>>() {
        }.getType());
        String EToken = bodydata.get("EToken");
        Message<String> M = new Gson().fromJson(bodydata.get("M"), new TypeToken<Message<String>>() {
        }.getType());
   System.out.println(body);
        int t = SecurityFunctions.generateRandom();
        String time2 = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(TpublicKey, ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(t).array()));

        String d = ip + ";" + device;

        Map<String, Object> result;
        if (M.getStatus() == 1) {      //scan
            TokenRequestMessage<String> tokenRequestMessage = new TokenRequestMessage<>();
            tokenRequestMessage.setToken(EToken);
            tokenRequestMessage.setDevice(d);
            tokenRequestMessage.setTime(time2);
            tokenRequestMessage.setMessage(new Message<String>().setOK().setMessage(M.getMessage()));

            result = request(tokenRequestMessage.toJson(), IP + "/qr/update");
        } else {        //confirm
            TokenRequestMessage<String> tokenRequestMessage = new TokenRequestMessage<>();
            tokenRequestMessage.setToken(EToken);
            tokenRequestMessage.setDevice(d);
            tokenRequestMessage.setTime(time2);
            tokenRequestMessage.setMessage(new Message<String>().setOK().setMessage(M.getMessage()));
            result = request(tokenRequestMessage.toJson(), IP + "/qr/update");
        }

        if ((boolean) result.get("status")){System.out.println(result.get("message"));
            return new Gson().toJson(new HashMap<>().put("M", new Message<String>().setStatus(2).setMessage((String) result.get("message")).toJson()));
        }
        Map<String, String> receive = new Gson().fromJson((String) result.get("message"), new TypeToken<Map<String, String>>() {
        }.getType());

        if (M.getStatus() == 1) {      //scan
            byte[] K = Utils.base64Decode(receive.get("K"));
            PublicKey Kcpub = SecurityFunctions.readPublicKey(K);
            String m = receive.get("M");
            Message<String> mes = new Gson().fromJson(m, new TypeToken<Message<String>>() {
            }.getType());
       System.out.println(mes.toJson());
            if (!mes.isOk())
                return new Gson().toJson(new HashMap<>().put("M", new Message<String>().setStatus(2).setMessage(mes.getMessage()).toJson()));

            int t1 = ByteBuffer.wrap(SecurityFunctions.decryptAsymmetric(privateKey, Utils.base64Decode(receive.get("T")))).order(ByteOrder.LITTLE_ENDIAN).getInt();
            if (t1 == t + 1) {
                String time = Utils.responseChallenge(bodydata.get("T"), Kcpub);
                Map<String, String> responseMap = new HashMap<>();
                responseMap.put("T", time);
                responseMap.put("M", new Message<String>().setOK().setMessage(mes.getMessage()).toJson());
            System.out.print("success");
                return new Gson().toJson(responseMap);
            }
            return new Gson().toJson(new HashMap<>().put("M", new Message<String>().setStatus(1).setMessage("Time authentication failed").toJson()));

        } else {
            byte[] K = Utils.base64Decode(receive.get("K"));
            PublicKey Kcpub = SecurityFunctions.readPublicKey(K);
            String m = receive.get("M");
            Message<String> jm = new Gson().fromJson(m, new TypeToken<Message<String>>() {
            }.getType());
       System.out.println(jm.toJson());
            if (!jm.isOk())
                return new Gson().toJson(new HashMap<>().put("M", new Message<String>().setStatus(2).setMessage(jm.getMessage()).toJson()));
            String message = jm.getMessage();

            String time = Utils.responseChallenge(bodydata.get("T"), Kcpub);
            Map<String, String> responseMap = new HashMap<>();
            responseMap.put("T", time);
            responseMap.put("M", new Message<String>().setOK().setMessage(message).toJson());
       System.out.println("success");
            return new Gson().toJson(responseMap);
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
        Map<String, String> bodydata = new Gson().fromJson(body, new TypeToken<Map<String, String>>() {
        }.getType());
        String nonce2 = bodydata.get("nonce2");

        String d = ip + ";" + device;
        int t = SecurityFunctions.generateRandom();
        String time2 = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(TpublicKey, ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(t).array()));

        Map<String, String> requestMap = new HashMap<>();
        requestMap.put("nonce2", nonce2);
        requestMap.put("system", systemid);
        requestMap.put("T", time2);
        requestMap.put("D", d);
        String content = new Gson().toJson(requestMap);
        String target_url = IP + "/qr/query";
        Map<String, String> responseMap = new HashMap<>();

        Map<String, Object> ereceive = request(content, target_url);

        if ((boolean) ereceive.get("status")) {
            responseMap.put("M", new Message<String>().setStatus(2).setMessage((String) ereceive.get("message")).toJson());
            return new Gson().toJson(responseMap);
        }
        Map<String, String> receive = new Gson().fromJson((String) ereceive.get("message"), new TypeToken<Map<String, Integer>>() {
        }.getType());
        //Base64.Decoder decoder = Base64.getDecoder();
        int t1 = ByteBuffer.wrap(
                SecurityFunctions.decryptAsymmetric(privateKey,Utils.base64Decode(receive.get("T"))))
                .order(ByteOrder.LITTLE_ENDIAN).getInt();


        if (t1 == t + 1) {
            Map<String, Object> tm = new Gson().fromJson(receive.get("M"), new TypeToken<Map<String, Object>>() {
            }.getType());
            int type = (int) (tm.get("type"));
            if (type == 2) {
                String etoken = receive.get("EToken");
                String kp = receive.get("KP");
                responseMap.put("M", new Message<String>().setStatus((int) tm.get("type")).setMessage((String) tm.get("message")).toJson());
                responseMap.put("EToken", etoken);
                responseMap.put("KP", kp);
                return new Gson().toJson(responseMap);
            } else
                return new Gson().toJson(new HashMap<>().put("M", new Message<String>().setStatus((int) tm.get("type")).setMessage((String) tm.get("message")).toJson()));
        } else
            return new Gson().toJson(new HashMap<>().put("M", new Message<String>().setError().setMessage("Time Authentication Failed").toJson()));
    }

    /**
     *
     */
    public String deinit(String body, String ip, String device) throws Exception {
        Map<String, String> data = new Gson().fromJson(body, new TypeToken<Map<String, String>>() {
        }.getType());
        String EToken = data.get("EToken");
        int t = SecurityFunctions.generateRandom();
        String time = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(TpublicKey, ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(t).array()));
        String D = ip + ";" + device;

        Map<String, String> requestMap = new HashMap<>();
        requestMap.put("EToken", EToken);
        requestMap.put("T", time);
        requestMap.put("D", D);
        String content = new Gson().toJson(requestMap);
        Map<String, Object> result = request(content, "/token/deinit");
        if ((boolean) result.get("status"))
            return "{\"M\":{\"status\":2,\"message\":\"" + result.get("message") + "\"}}";

        Map<String, String> receive = new Gson().fromJson((String) result.get("message"), new TypeToken<Map<String, String>>() {
        }.getType());
        int t1 = ByteBuffer.wrap(SecurityFunctions.decryptAsymmetric(privateKey, Base64.getDecoder().decode(receive.get("T")))).order(ByteOrder.LITTLE_ENDIAN).getInt();

        if (t1 == t + 1) {
            String M = receive.get("M");
            Message<String> m = new Gson().fromJson(M, new TypeToken<Message<String>>() {
            }.getType());
            if (m.getStatus() == 1)
                return "{\"M\":{\"status\":2,\"message\":\"" + m.getMessage() + "\"}}";
            return "{\"M\":{\"status\":0,\"message\":\"" + m.getMessage() + "\"}}";
        }
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
        int t = SecurityFunctions.generateRandom();
        String time2 = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(TpublicKey,
                ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(t).array()));

        String d = ip + ";" + device;
        TokenRequestMessage<String> tokenRequestMessage = new TokenRequestMessage<>();
        tokenRequestMessage.setToken(etoken);
        tokenRequestMessage.setDevice(d);
        tokenRequestMessage.setTime(time2);

        String target_url = IP + "/user/log";
        Map<String, String> responseMap = new HashMap<>();

        Map<String, Object> ereceive = request(new Gson().toJson(tokenRequestMessage), target_url);

        if ((boolean) ereceive.get("status")) {
            responseMap.put("M", new Message<String>().setStatus(2).setMessage((String) ereceive.get("message")).toJson());
            return new Gson().toJson(responseMap);
        }
        Map<String, String> receive = new Gson().fromJson((String) ereceive.get("message"), new TypeToken<Map<String, Integer>>() {
        }.getType());

        int t1 = ByteBuffer.wrap(
                SecurityFunctions.decryptAsymmetric(privateKey, decoder.decode(receive.get("T"))))
                .order(ByteOrder.LITTLE_ENDIAN).getInt();

        if (t1 == t + 1) {
            byte[] K = Utils.base64Decode(receive.get("K"));
            PublicKey Kcpub = SecurityFunctions.readPublicKey(K);
            String m = receive.get("M");
            String time = Utils.responseChallenge(bodydata.get("T"), Kcpub);
            responseMap.put("M", m);
            responseMap.put("T", time);

        } else {
            responseMap.put("M", new Message<String>().setStatus(1).setMessage("time authentiaction failed").toJson());
        }
        return new Gson().toJson(responseMap);
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
        int t = SecurityFunctions.generateRandom();
        String time2 = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(TpublicKey,
                ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(t).array()));
        String d = ip + ";" + device;

        TokenRequestMessage<String> tokenRequestMessage = new TokenRequestMessage<>();
        tokenRequestMessage.setToken(etoken);
        tokenRequestMessage.setDevice(d);
        tokenRequestMessage.setTime(time2);


        String target_url = IP + "/token/list";
        Map<String, String> responseMap = new HashMap<>();

        Map<String, Object> ereceive = request(new Gson().toJson(tokenRequestMessage), target_url);

        if ((boolean) ereceive.get("status")) {
            responseMap.put("M", new Message<String>().setStatus(2).setMessage((String) ereceive.get("message")).toJson());
            return new Gson().toJson(responseMap);
        }
        Map<String, String> receive = new Gson().fromJson((String) ereceive.get("message"), new TypeToken<Map<String, Integer>>() {
        }.getType());

        int t1 = ByteBuffer.wrap(
                SecurityFunctions.decryptAsymmetric(privateKey, decoder.decode(receive.get("T"))))
                .order(ByteOrder.LITTLE_ENDIAN).getInt();

        if (t1 == t + 1) {
            byte[] K = Utils.base64Decode(receive.get("K"));
            PublicKey Kcpub = SecurityFunctions.readPublicKey(K);
            String m = receive.get("M");
            String time = Utils.responseChallenge(bodydata.get("T"), Kcpub);
            responseMap.put("M", m);
            responseMap.put("T", time);

        } else {
            responseMap.put("M", new Message<String>().setStatus(1).setMessage("time authentiaction failed").toJson());
        }
        return new Gson().toJson(responseMap);
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
        int t = SecurityFunctions.generateRandom();
        String time2 = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(TpublicKey,
                ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(t).array()));
        String d = ip + ";" + device;

        TokenRequestMessage<String> tokenRequestMessage = new TokenRequestMessage<String>();
        tokenRequestMessage.setToken(etoken);
        tokenRequestMessage.setDevice(d);
        tokenRequestMessage.setTime(time2);
        tokenRequestMessage.setMessage(new Message<String>(Integer.parseInt(cm.get("status")), cm.get("message")));

        String target_url = IP + "/token/revoke";
        Map<String, String> responseMap = new HashMap<>();

        Map<String, Object> ereceive = request(new Gson().toJson(tokenRequestMessage), target_url);

        if ((boolean) ereceive.get("status")) {
            responseMap.put("M", new Message<String>().setStatus(2).setMessage((String) ereceive.get("message")).toJson());
            return new Gson().toJson(responseMap);
        }
        Map<String, String> receive = new Gson().fromJson((String) ereceive.get("message"), new TypeToken<Map<String, Integer>>() {
        }.getType());

        int t1 = ByteBuffer.wrap(
                SecurityFunctions.decryptAsymmetric(privateKey, decoder.decode(receive.get("T"))))
                .order(ByteOrder.LITTLE_ENDIAN).getInt();

        if (t1 == t + 1) {
            byte[] K = Utils.base64Decode(receive.get("K"));
            PublicKey Kcpub = SecurityFunctions.readPublicKey(K);
            String mm = receive.get("M");
            String time = Utils.responseChallenge(bodydata.get("T"), Kcpub);
            responseMap.put("M", mm);
            responseMap.put("T", time);

        } else {
            responseMap.put("M", new Message<String>().setStatus(1).setMessage("time authentiaction failed").toJson());
        }
        return new Gson().toJson(responseMap);
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
        int t = SecurityFunctions.generateRandom();
        String time2 = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(TpublicKey,
                ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(t).array()));
        String d = ip + ";" + device;

        TokenRequestMessage<String> tokenRequestMessage = new TokenRequestMessage<String>();
        tokenRequestMessage.setToken(etoken);
        tokenRequestMessage.setDevice(d);
        tokenRequestMessage.setTime(time2);


        String target_url = IP + "/keys/regen";
        Map<String, String> responseMap = new HashMap<>();

        Map<String, Object> ereceive = request(new Gson().toJson(tokenRequestMessage), target_url);

        if ((boolean) ereceive.get("status")) {
            responseMap.put("M", new Message<String>().setStatus(2).setMessage((String) ereceive.get("message")).toJson());
            return new Gson().toJson(responseMap);
        }
        Map<String, String> receive = new Gson().fromJson((String) ereceive.get("message"), new TypeToken<Map<String, Integer>>() {
        }.getType());

        int t1 = ByteBuffer.wrap(
                SecurityFunctions.decryptAsymmetric(privateKey, decoder.decode(receive.get("T"))))
                .order(ByteOrder.LITTLE_ENDIAN).getInt();

        if (t1 == t + 1) {
            byte[] K = Utils.base64Decode(receive.get("K"));
            PublicKey Kcpub = SecurityFunctions.readPublicKey(K);
            String m = receive.get("M");
            String time = Utils.responseChallenge(bodydata.get("T"), Kcpub);
            responseMap.put("M", m);
            responseMap.put("T", time);

        } else {
            responseMap.put("M", new Message<String>().setStatus(1).setMessage("time authentiaction failed").toJson());
        }
        return new Gson().toJson(responseMap);
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
        connection.setRequestProperty("Content-Type","application/json");
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
