package io.tomahawkd.pki.api.server.util;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import io.tomahawkd.pki.api.server.Token;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

public class TokenUtils {

    public static String tokenResponse(String url, String body, String ip, String device,
                                           PublicKey TpublicKey,
                                           PrivateKey key) throws Exception {

        Map<String, String> bodydata = new Gson().fromJson(body, new TypeToken<Map<String, String>>() {
        }.getType());

        int t = SecurityFunctions.generateRandom();
        String time2 = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(TpublicKey,
                ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(t).array()));

        TokenRequestMessage<String> tokenRequestMessage = new TokenRequestMessage<>();
        tokenRequestMessage.setToken(bodydata.get("EToken"));
        tokenRequestMessage.setDevice(ip + ";" + device);
        tokenRequestMessage.setTime(time2);
        tokenRequestMessage.setRawMessage(bodydata.get("M"));

        Map<String, String> responseMap = new HashMap<>();

        Map<String, Object> ereceive = Token.request(new Gson().toJson(tokenRequestMessage), url);

        if ((boolean) ereceive.get("status")) {
            responseMap.put("M",
                    new Message<String>().setStatus(2)
                            .setMessage((String) ereceive.get("message")).toJson());
            return new Gson().toJson(responseMap);
        }
        TokenResponseMessage<Object> receive = new Gson().fromJson((String) ereceive.get("message"),
                new TypeToken<TokenResponseMessage<Object>>() {
                }.getType());

        int t1 = ByteBuffer.wrap(
                SecurityFunctions.decryptAsymmetric(key, Utils.base64Decode(receive.getTime())))
                .order(ByteOrder.LITTLE_ENDIAN).getInt();

        if (t1 == t + 1) {
            byte[] K = Utils.base64Decode(receive.getClientKey());
            PublicKey Kcpub = SecurityFunctions.readPublicKey(K);
            String time = Utils.responseChallenge(bodydata.get("T"), Kcpub);
            responseMap.put("M", receive.getRawMessage());
            responseMap.put("T", time);

        } else {
            responseMap.put("M", new Message<String>().setStatus(1)
                    .setMessage("time authentiaction failed").toJson());
        }
        return new Gson().toJson(responseMap);
    }
}
