package io.tomahawkd.pki;

import io.tomahawkd.pki.exceptions.CipherErrorException;
import io.tomahawkd.pki.util.FileUtil;
import io.tomahawkd.pki.util.SecurityFunctions;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.Objects;

@SpringBootApplication
public class PkiApplication {

	public static void main(String[] args)
			throws CipherErrorException, IOException {

		Path path = Paths.get(FileUtil.rootPath + "/resources");
		File f = path.toFile();

		File[] list = Objects.requireNonNull(
				f.listFiles((dir, name) -> name.endsWith(".pub") || name.endsWith(".pri")),
				"resources should be a dir");

		if (list.length != 2) {
			for (File fileToDelete : list) {
				fileToDelete.delete();
			}

			SecurityFunctions.generateNewAuthenticateServerKeys();
		}

		// Test keys
		KeyPair kp = SecurityFunctions.readAuthenticateServerKeys();

		byte[] enc = SecurityFunctions.encryptAsymmetric(kp.getPublic(), "1".getBytes());
		byte[] dec = SecurityFunctions.decryptAsymmetric(kp.getPrivate(), enc);

		assert Arrays.toString(dec).equals("1");

		System.out.println("OK: Authenticate Server key pair check passed.");

		// Alright, launch the server
		SpringApplication.run(PkiApplication.class, args);
	}

}
