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

@SpringBootApplication
public class PkiApplication {

	public static void main(String[] args)
			throws CipherErrorException, IOException {

		Path path = Paths.get(FileUtil.rootPath + "/resources");
		File f = path.toFile();

		File[] list =
				f.listFiles((dir, name) -> name.endsWith(".pub") || name.endsWith(".pri") || name.endsWith(".key"));

		if (list == null || list.length != 3) {

			if (list != null)
				for (File fileToDelete : list) {
					fileToDelete.delete();
				}

			SecurityFunctions.generateNewAuthenticateServerKeys(FileUtil.rootPath + "/resources/");
		}

		// Alright, launch the server
		SpringApplication.run(PkiApplication.class, args);
	}

}
