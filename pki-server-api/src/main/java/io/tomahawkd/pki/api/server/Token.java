package io.tomahawkd.pki.api.server;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import io.tomahawkd.pki.api.server.util.Message;
import io.tomahawkd.pki.api.server.util.SecurityFunctions;
import org.omg.CORBA.OBJ_ADAPTER;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Map;

@RestController
@RequestMapping("/api/token")
public class Token {
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private PublicKey TpublicKey;
    private String Kcs;
    public   static String systemid;
   // private String systemid = "a5e1fc6f2f4941fe981e0361a99ded64";


    private static Token instance;

    public static Token getInstance() {
        if (instance == null) instance = new Token();
        return instance;
    }

    public static void setApiKey(String api) {
        systemid = api;
    }

    private Token() {
        try {
            TpublicKey = SecurityFunctions.readPublicKey(this.getTPublicKey());
        } catch (Exception e) {
        }

    }

    /**
     *
     **/
    public String publicKeyDistribute(String body) throws Exception {

        if(TpublicKey==null)
            TpublicKey = SecurityFunctions.readPublicKey(this.getTPublicKey());
        return  TpublicKey.toString();

    }
    /**
     * @Param data {"payload": "Base64 encoded Ks public key encrypted (username,password)",
     *              "S": "Base64 encoded Ks public key encrypted (Kc,s,time1)",
     *              "K": "Base64 encoded Kt public key encrypted Kc,t",
     *              "iv": "Base64 encoded Kt public key encrypted iv"}
     * @return
     * {"EToken": "Base64 encoded Kc public key encrypted token",
     *  "M": {"status": (number 0,1,2),"message": "status description"},
     *  "KP": "Base64 encoded Kc,t encrypted (Kc public key,Kc private key)",
     *  "T1": "Base64 encoded Kc public key encrypted (time1+1)"}
     */
    @PostMapping("/init")
    public String acceptInitializeAuthenticationMessage(@RequestParam String body, HttpServletRequest request, ThrowableBiFunction<String, Integer> callback) throws Exception {
        Map<String, String> bodyData =
                new Gson().fromJson(body, new TypeToken<Map<String, String>>() {
                }.getType());
        Base64.Decoder decoder = Base64.getDecoder();
        String payload = bodyData.get("payload");

        int usrid = callback.apply(payload);
        if(usrid == -1)
            return "{\"M\":{\"status\":4,\"message\":\"user function failed\"}}";

        String eS = new String(decoder.decode(bodyData.get("S")), StandardCharsets.UTF_8);
        String time1 = new String(SecurityFunctions.decryptAsymmetric(privateKey,eS.getBytes()));

        String K = bodyData.get("K");
        String iv = new String(decoder.decode(bodyData.get("iv")), StandardCharsets.UTF_8);
        int t = SecurityFunctions.generateRandom();
        String time2 = new String((SecurityFunctions.encryptAsymmetric(TpublicKey,
                ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(t).array())), StandardCharsets.UTF_8);
        //String time2 = new String(SecurityFunctions.encryptAsymmetric(TpublicKey,String.valueOf(timestamp).getBytes()),"UTF-8");
        String userid = String.valueOf(usrid);     //userid获得
            //systemid获得
        //加密payload userid和systemid
        String idc = userid + ";" + systemid;
        String eidc = new String(SecurityFunctions.encryptAsymmetric(TpublicKey,idc.getBytes()));
        String device = request.getHeader("User-Agent"); //改
        String id = request.getRemoteAddr();     //改
        String  D = device + ";" + id;
        //encode K,idc,time2
        Base64.Encoder encoder = Base64.getEncoder();
        String encid = encoder.encodeToString(iv.getBytes());
        String encidc =  encoder.encodeToString(eidc.getBytes());
        String enctime2 = encoder.encodeToString(time2.getBytes());

        String target_url = "/token/init";
        StringBuilder target = new StringBuilder(target_url);
        URL url = new URL(target.toString());
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setDoOutput(true);
        String content = "{\"K\":\"" + K + "\",\"id\":\"" + encid + "\",\"idc\":\"" + encidc + "\",\"D\":\"" + D + "\",\"T\":\"" + enctime2 + "\"}";
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
        String m = result.get("M");
        Map<String,Object> message = new Gson().fromJson(m,new TypeToken<Map<String,Integer>>(){}.getType());
        if((int)message.get("status") == 0){
            String etoken = result.get("EToken");
            String KP = result.get("KP");
            String T = new String(SecurityFunctions.decryptAsymmetric(privateKey,new String(decoder.decode(result.get("T")), StandardCharsets.UTF_8).getBytes()));
            String k = new String(decoder.decode(result.get("K")), StandardCharsets.UTF_8);
            PublicKey Kcpub = SecurityFunctions.readPublicKey(k);
            int t1 = ByteBuffer.wrap(T.getBytes()).order(ByteOrder.LITTLE_ENDIAN).getInt();
            if((t1 == t + 1)){
                int tem = ByteBuffer.wrap(time1.getBytes()).order(ByteOrder.LITTLE_ENDIAN).getInt();
                String time = new String((SecurityFunctions.encryptAsymmetric(Kcpub,
                        ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(tem).array())), StandardCharsets.UTF_8);
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
    @PostMapping("/validate")
    public String authentication(@RequestParam String body,HttpServletRequest request, ReturnDataFunction<String,String,String> callback) throws Exception {
        Map<String,String> bodydata = new Gson().fromJson(body,new TypeToken<Map<String,String>>(){}.getType());
        Base64.Decoder decoder = Base64.getDecoder();
        String payload = new String(decoder.decode(bodydata.get("payload")), StandardCharsets.UTF_8);
        String etoken = bodydata.get("EToken");
        String T = bodydata.get("T");
        String time1 = new String(SecurityFunctions.decryptAsymmetric(privateKey,T.getBytes()), StandardCharsets.UTF_8);
        int t = SecurityFunctions.generateRandom();
        String time2 = new String((SecurityFunctions.encryptAsymmetric(TpublicKey,
                ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(t).array())), StandardCharsets.UTF_8);
        String device = request.getHeader("User-Agent");
        String id = request.getRemoteAddr();
        String d = device + ";" + id;

        String target_url = "/token/validate";
        StringBuilder target = new StringBuilder(target_url);
        URL url = new URL(target.toString());
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setDoOutput(true);
        String content = "{\"EToken\":\"" + etoken + "\",\"D\":\"" + d + "\",\"T\":\"" + Base64.getEncoder().encodeToString(time2.getBytes()) +  "\"}";
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
        String M = receive.get("M");
        Map<String,String> message = new Gson().fromJson(M,new TypeToken<Map<String,Integer>>(){}.getType());
        String K = new String(decoder.decode(receive.get("K")), StandardCharsets.UTF_8);
        String T2 = new String(SecurityFunctions.decryptAsymmetric(privateKey,decoder.decode(receive.get("T"))), StandardCharsets.UTF_8);
        int t1 = ByteBuffer.wrap(T2.getBytes()).order(ByteOrder.LITTLE_ENDIAN).getInt();
        PublicKey Kcpub = SecurityFunctions.readPublicKey(K);
        if(t1 == t + 1){
            String data = callback.apply(message.get("message"),payload);
            int tem = ByteBuffer.wrap(time1.getBytes()).order(ByteOrder.LITTLE_ENDIAN).getInt();
            String time = new String((SecurityFunctions.encryptAsymmetric(Kcpub,
                    ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(tem).array())), StandardCharsets.UTF_8);
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
    @PostMapping("/scan")
    public String scanner(@RequestParam String body,HttpServletRequest request) throws Exception {
        Base64.Decoder decoder = Base64.getDecoder();
        Map<String,String> bodydata = new Gson().fromJson(body,new TypeToken<Map<String,String>>(){}.getType());
        String EToken = bodydata.get("EToken");
        String N = bodydata.get("N");
        String time1 = new String(SecurityFunctions.decryptAsymmetric(privateKey,decoder.decode(bodydata.get("T").getBytes())), StandardCharsets.UTF_8);
        int time2 = SecurityFunctions.generateRandom();
        String time = new String(SecurityFunctions.encryptAsymmetric(TpublicKey,ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(time2).array()), StandardCharsets.UTF_8);
        String sysid = Base64.getEncoder().encodeToString(systemid.getBytes());
        String device = request.getHeader("User-Agent");
        String id = request.getRemoteAddr();
        String d = device + ";" + id;
        String content = "{\"M\":{\"status\":1,\"message\":\"" + N + "\"},\"systemid\":\"" + sysid + "\"," +
                "\"EToken\":\"" + EToken + "\",\"T\":\"" + Base64.getEncoder().encodeToString(time.getBytes()) +
                "\",\"D\":\"" + d + "\"}";
        String target_url = "/qr/update";
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
        PublicKey Kcpub = SecurityFunctions.readPublicKey(Kc);
        String M = receive.get("M");
        Map<String,Object> mes = new Gson().fromJson(M,new TypeToken<Map<String,Object>>(){}.getType());
        if((int)mes.get("status") == 1)
            return "\"M\":{\"status\":3,\"message\":\"" + mes.get("message") + "\"}";
        String T1 = new String(SecurityFunctions.decryptAsymmetric(privateKey,decoder.decode(receive.get("T"))) ,"UTF-8");
        int authtime = ByteBuffer.wrap(T1.getBytes()).order(ByteOrder.LITTLE_ENDIAN).getInt();
        if(authtime == time2 + 1){
            //需要用Kcpub加密
            int tem = ByteBuffer.wrap(time1.getBytes()).order(ByteOrder.LITTLE_ENDIAN).getInt();
            String time_1 = new String((SecurityFunctions.encryptAsymmetric(Kcpub,
                    ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(tem).array())),"UTF-8");
            //String time_1 = new String(SecurityFunctions.encryptAsymmetric(Kcpub,String.valueOf(Long.parseLong(time1) + 1).getBytes()),"UTF-8") ;
            String T_1 = Base64.getEncoder().encodeToString(time_1.getBytes());
            return "{\"M\":" + mes.get("message") + ",\"T\":\"" + T_1 + "\"}";
        }
        return "\"M\":{\"status\":1,\"message\":\"time authentiaction failed\"}";
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
    @PostMapping("/confirm")
    public String confirmLogin(@RequestParam String body,HttpServletRequest request) throws Exception{
        Base64.Decoder decoder = Base64.getDecoder();
        Map<String,String> bodydata = new Gson().fromJson(body,new TypeToken<Map<String,String>>(){}.getType());
        String EToken = bodydata.get("EToken");
        String M = bodydata.get("M");
        String time1 = new String(SecurityFunctions.decryptAsymmetric(privateKey,decoder.decode(bodydata.get("T").getBytes())),"UTF-8");
        int time2 = SecurityFunctions.generateRandom();
        String time = new String(SecurityFunctions.encryptAsymmetric(TpublicKey,ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(time2).array()),"UTF-8");
        String sysid = Base64.getEncoder().encodeToString(systemid.getBytes());

        String device = request.getHeader("User-Agent");
        String id = request.getRemoteAddr();
        String d = device + ";" + id;
        String content = "{\"M\":{\"status\":2,\"message\":\"" + M + "\"},\"EToken\":\"" + EToken + "\",\"systemid\":\"" + sysid + "\"," +
                "\"T\":\"" + Base64.getEncoder().encodeToString(time.getBytes()) +
                "\",\"D\":\"" + d + "\"}";
        String target_url = "/qr/update";
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
        PublicKey Kcpub = SecurityFunctions.readPublicKey(Kc);
        String m = receive.get("M");
        Map<String,Object> jm = new Gson().fromJson(m,new TypeToken<Map<String, Object>>(){}.getType());
        if((int)jm.get("status") == 1)
            return "{\"M\":{\"status\":3,\"message\":\"" + jm.get("message") + "\"}}";
        String message = (String)jm.get("message");
        int tem = ByteBuffer.wrap(time1.getBytes()).order(ByteOrder.LITTLE_ENDIAN).getInt();
        String time_1 = new String((SecurityFunctions.encryptAsymmetric(Kcpub,
                ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(tem).array())),"UTF-8");
        //需要用Kcpub加密
        //String time_1 = new String(SecurityFunctions.encryptAsymmetric(publicKey,String.valueOf(Long.parseLong(time1) + 1).getBytes()),"UTF-8") ;
        String T_1 = Base64.getEncoder().encodeToString(time_1.getBytes());
        return "{\"M\":" + message + ",\"T\":\"" + T_1 + "\"}";
    }
    /**
     * @return
     *
     * @Param
     */
    public String rolling(String body) throws Exception {
        String target_url = "/qr/query";
        StringBuilder target = new StringBuilder(target_url);
        URL url = new URL(target.toString());
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setDoOutput(true);
        OutputStream os = connection.getOutputStream();
        byte[] input = body.getBytes(StandardCharsets.UTF_8);
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
        }
        BufferedReader buff = new BufferedReader(in);
        String line = buff.readLine();
        while (line != null) {
            text.append(line).append("\r\n");
            line = buff.readLine();
        }
        if (error)
            return "{\"M\":{\"status\":2,\"message\":\"" + text.toString() + "\"}}";
        return text.toString();
    }

    /**
     * @return
     *
     * @Param
     */
    public String pollingInitialization(String body) throws Exception {
        String target_url = "/qr/query";
        StringBuilder target = new StringBuilder(target_url);
        URL url = new URL(target.toString());
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setDoOutput(true);
        OutputStream os = connection.getOutputStream();
        byte[] input = body.getBytes(StandardCharsets.UTF_8);
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
        }
        BufferedReader buff = new BufferedReader(in);
        String line = buff.readLine();
        while (line != null) {
            text.append(line).append("\r\n");
            line = buff.readLine();
        }
        if (error)
            return "{\"M\":{\"status\":2,\"message\":\"" + text.toString() + "\"}}";
        return text.toString();
    }

    private  String getTPublicKey()throws  Exception{
        File file = new File("G:/a.txt");
        if (!file.exists()) {       // 向服务器获取   并写入文件
            String target_url = "/auth";
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
            }
            BufferedReader buff = new BufferedReader(in);
            String line = buff.readLine();
            while (line != null) {
                text.append(line).append("\r\n");
                line = buff.readLine();
            }
            if (error)
                return "{\"M\":{\"status\":2,\"message\":\"public key accept failed\"}}";
            Base64.Decoder decoder = Base64.getDecoder();
            String publickey = new String(decoder.decode(text.toString()), "UTF-8");

            try {
                file.createNewFile();
                FileWriter writer = new FileWriter(file);
                writer.write("");//清空原文件内容
                writer.write(publickey);
                writer.flush();
                writer.close();
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            return publickey;
        } else {  //从文件中读取出来并返回
            FileReader reader = new FileReader(file);//定义一个fileReader对象，用来初始化BufferedReader
            BufferedReader bReader = new BufferedReader(reader);//new一个BufferedReader对象，将文件内容读取到缓存
            StringBuilder sb = new StringBuilder();//定义一个字符串缓存，将字符串存放缓存中
            String s = "";
            while ((s = bReader.readLine()) != null) {//逐行读取文件内容，不读取换行符和末尾的空格
                sb.append(s + "\n");//将读取的字符串添加换行符后累加存放在缓存中
            }
            bReader.close();
            return sb.toString();
        }
    }
}
