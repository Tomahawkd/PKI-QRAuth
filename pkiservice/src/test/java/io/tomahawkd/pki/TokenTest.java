package io.tomahawkd.pki;

import com.google.gson.Gson;
import io.tomahawkd.pki.exceptions.CipherErrorException;
import io.tomahawkd.pki.exceptions.MalformedJsonException;
import io.tomahawkd.pki.util.Utils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.test.context.junit4.SpringRunner;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class TokenTest {

	@Autowired
	private TestRestTemplate testRestTemplate;

	@Test
	public void token()
			throws InvalidKeySpecException, NoSuchAlgorithmException, CipherErrorException, MalformedJsonException {

		String auth = this.testRestTemplate.getForObject("/keys/auth", String.class);
		System.out.println(auth);
		PublicKey k = SecurityFunctions.readPublicKey(auth);

		byte[] iv = SecurityFunctions.generateRandom(16);
		byte[] kct = SecurityFunctions.generateRandom(32);
		String ivString = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(k, iv));
		String kctString = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(k, kct));

		String userTag = Utils.base64Encode(SecurityFunctions.generateHash("1"));
		String system = "a5e1fc6f2f4941fe981e0361a99ded64";
		String idString =
				Utils.base64Encode(SecurityFunctions.encryptAsymmetric(k, (userTag + ";" + system).getBytes()));

		int t = SecurityFunctions.generateRandom();
		String tString = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(k,
				ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(t).array()));

		Map<String, String> request = new HashMap<>();
		request.put("K", kctString);
		request.put("iv", ivString);
		request.put("id", idString);
		request.put("T", tString);
		request.put("D", "JavaTest;127.0.0.1");

		String re = new Gson().toJson(request);
		System.out.println(re);
		String res = this.testRestTemplate.postForObject("/token/init", re, String.class);

		System.out.println(res);
		Map<String, String> result = Utils.wrapMapFromJson(res);
		System.out.println(result.get("M"));
		assertThat(result.get("M")).contains("\"status\":0");

		String tR = result.get("T");
		PrivateKey kpr = SecurityFunctions.readPrivateKey("MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDHFswBtRdW5nFU1sRjG7MYJqT0su6hWWI/Iz+MWtBlak8VGKdK93FrrF/1nKY858rwgm5k8xhUPjiUNKawChWMEsgVRYUY4PlO85Y9cYdWSJ3vnIjZx/SPH02xfD+oXOI8fcTxOwvm1lPUiWfGZsjG2xtES/dx51LpDtNBY0Ym4IF5GtRKn2chlPyptGldePp/Ue945bU7iQ8KamXKNYe5Uplx0LzqitCvdlrcKHCOKA/m2DQ4NsZnIcEK93hyf11WC8uCZCtJXTRwuFGw68sxKgt2KMwp9CTrAtejqgt4r/b2OOUWy3HvmQpX38J7ql5XJMPZCMVGnUl2NLAS9g29AgMBAAECggEASc9I2QUzXvNWZvasnnXBgx2ooFPKJqWFyBSgVb/BbSfpo8+dDi0IrrucY+mss/3Xfi1NEj4R8gGTZlbSyYcjj+fSqBg7DQszQrMKK0NwwmtvqkrlbaA1Ke6YFkoTK68r7PNP1YNnmTAyqiQ7BhJLM3Y9+KcVWPRDB8aIScCtXHHNxuPp8QsI3GxB9gRNDpq5/mMjx+5LBBKXPAC8HXwWd18Kl2JUUQtmlk9OuLsmUkUnYy+8v2paohDqxYGF+WOEVs1xviCaQJ4xMGmsH17UoKhPUGw4EMxPWtPLzFhv0m6RK5AC7Xxx0IhW91ksNoVq+ncKHJTPeOieGcUO6c2EYQKBgQDupr77QN0jrdE8V3d3QxVwHzBB7IUkLaYfva76NyMjvEIioEt+HhsAWYl7/skV6NETdZfTcPOckjEL5Hmb3X8PmxkIlVH+dtbk/nqR+Zga+yBUky6gJh9afApZwXSa/Jsqtv3QDrgtUOjbWLWXIC8IHCggyWO3AfHRveryZ9ttBQKBgQDVj83qVB/I1jF+PBvvTSpalO1tPqPHMkMIbtwEqhIFtzFhPwZe3fjc81wHKmTf4huo8FQHZcIwM6qJpvJl/JFRPEiNeDA7KPBD5GHXLhI/XMUc7DumV0uw6cT5KBfqO5hY9Sio2a4bJjmtQZrkH/H1pUQhTN80dGXwSwELPOk7WQKBgClYZhntYOJ/iJJlrOLSknI8VQX2zhI4fmFdYWUkDEhyoxqQnsOYv6DN4k3DFF9hWGeApe8R0IK9qRWgXZktRIgVnL6p7+yf9hbyJ5YGod16yF0eqqNAN4pblwd5xpPbU56Q2WQkSLBBJjZqJfuqrbs/9YvImCfqhFSMDJo2eANpAoGBAMmSvEcrM/z6vyhpT+ylJw7sdtWgRDHmLQMusBju9afTa5ZgSIEOfrD+OqTAzQnMf1ML1CRPVeTtP1BB9ZVxuS+1+L0e7ldIos9SJ09VOv/3bk2IZBzzVIwdej+6Kih6K6f7bm9BV2ZkxBfWTn538IdtgEr2Jc969iTChq+2xGWxAoGAdQVu4t5cbNXjM0wQNQdq8jhWMjKPVMUSZNJozxT/Z2KuRewYYaoMpL7YFCYOllDpk2suPXM4SNAm7vo+zAo6LH/+uGUnHGrykiYB6Shn/dTx4gwZOpuFfT5I7U6fbIh7XGSLpaxuAmHEEXLm58BOxSMVN2w/BknbvEDa7GyrfDs=");
		int tRes = ByteBuffer.wrap(SecurityFunctions.decryptAsymmetric(kpr, Utils.base64Decode(tR)))
				.order(ByteOrder.LITTLE_ENDIAN).getInt();
		assertThat(tRes).isEqualTo(t + 1);

		String[] kp =
				new String(SecurityFunctions.decryptSymmetric(kct, iv, Utils.base64Decode(result.get("KP"))))
						.split(";");
		KeyPair keyPair = SecurityFunctions.readKeysFromString(kp[1], kp[0]);


		byte[] etoken = SecurityFunctions.decryptAsymmetric(keyPair.getPrivate(),
				Utils.base64Decode(result.get("EToken")));

		int nonce = ByteBuffer.wrap(etoken).order(ByteOrder.LITTLE_ENDIAN).getInt();
		byte[] token = new byte[etoken.length - Integer.BYTES];
		System.arraycopy(etoken, Integer.BYTES, token, 0, etoken.length - Integer.BYTES);

		nonce++;
		byte[] tokenArr = ByteBuffer.allocate(token.length + Integer.BYTES)
				.order(ByteOrder.LITTLE_ENDIAN).putInt(nonce).put(token).array();
		String etokenReq = Utils.base64Encode(
				SecurityFunctions.encryptAsymmetric(k, tokenArr));

		int tReq = SecurityFunctions.generateRandom();
		String tStringReq = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(k,
				ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(tReq).array()));

		Map<String, String> reqMap = new HashMap<>();
		reqMap.put("EToken", etokenReq);
		reqMap.put("T", tStringReq);
		reqMap.put("D", "JavaTest;127.0.0.1");

		String reqJ = new Gson().toJson(reqMap);
		System.out.println(reqJ);
		String resAuth = this.testRestTemplate.postForObject("/token/validate", reqJ, String.class);
		System.out.println(resAuth);

		Map<String, String> resultAuth = Utils.wrapMapFromJson(resAuth);
		System.out.println(resultAuth.get("M"));
		assertThat(resultAuth.get("M")).contains("\"status\":0");

		String tRes2 = resultAuth.get("T");
		int tRes2Int = ByteBuffer.wrap(SecurityFunctions.decryptAsymmetric(kpr, Utils.base64Decode(tRes2)))
				.order(ByteOrder.LITTLE_ENDIAN).getInt();
		assertThat(tRes2Int).isEqualTo(tReq + 1);
	}
}
