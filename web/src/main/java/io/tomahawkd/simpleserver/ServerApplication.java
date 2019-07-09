package io.tomahawkd.simpleserver;

import io.tomahawkd.pki.api.server.Token;

import io.tomahawkd.pki.api.server.util.FileUtil;
import io.tomahawkd.pki.api.server.util.Utils;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.io.IOException;
import java.util.Base64;

@SpringBootApplication
public class ServerApplication {

	public static void main(String[] args) throws Exception {

		Token.setApiKey("cab4af0fc499491eb9bb16120e3ae195");

		byte[] pubBytes = Base64.getDecoder().decode(
				FileUtil.readFile("./web/src/main/resources/public.pub"));
		Token.readPublicKey(pubBytes);

		byte[] priBytes = Utils.base64Decode(
				FileUtil.readFile("./web/src/main/resources/private.pri"));
		Token.readPrivateKey(priBytes);



		Token.readTPublicKey();




		SpringApplication.run(ServerApplication.class, args);
	}

}
