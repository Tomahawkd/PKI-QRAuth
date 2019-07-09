package io.tomahawkd.pki.api.server.util;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;

public class FileUtil {

	public static final String rootPath = "./src/main";


	public static String readFile(String path) throws IOException {

		Path p = Paths.get(path);

		File file = p.toFile();
		if (!file.exists()) {
			throw new FileNotFoundException("File Not Found.");
		}
		if (!file.canRead()) {
			throw new FileSystemException("File Cannot be read.");
		}

		try {
			return new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
		} catch (IOException e) {
			throw new IOException(e.getMessage());
		}
	}

	public static void writeFile(String path, String data, boolean overwrite) throws IOException {

		Path p = Paths.get(path);
		File file = p.toFile();

		if (file.exists()) {
			if (overwrite) {
				if (!file.delete()) {
					throw new FileSystemException("File cannot be deleted.");
				}
			} else {
				Files.write(p, data.getBytes(StandardCharsets.UTF_8), StandardOpenOption.APPEND);
			}
		}

		if (!file.exists()) {
			Files.write(p, data.getBytes(StandardCharsets.UTF_8), StandardOpenOption.CREATE_NEW);
		}
	}
}
