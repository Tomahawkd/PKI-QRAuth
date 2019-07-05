//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package io.tomahawkd.pki.api.client.util;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.Charset;

public class httpUtil {
    public httpUtil() {
    }

    public static String getJsonData(String jsonObject, String urls) {
        StringBuffer sb = new StringBuffer();

        try {
            URL url = new URL(urls);
            HttpURLConnection conn = (HttpURLConnection)url.openConnection();
            conn.setDoOutput(true);
            conn.setDoInput(true);
            conn.setUseCaches(false);
            conn.setConnectTimeout(3000);
            conn.setReadTimeout(3000);
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Connection", "Keep-Alive");
            conn.setRequestProperty("Charset", "UTF-8");
            byte[] data = jsonObject.getBytes();
            conn.setRequestProperty("Content-Length", String.valueOf(data.length));
            conn.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
            conn.setRequestProperty("accept", "application/json");
            conn.connect();
            OutputStream out = new DataOutputStream(conn.getOutputStream());
            out.write(jsonObject.getBytes());
            out.flush();
            out.close();
            if (200 == conn.getResponseCode()) {
                InputStream in1 = conn.getInputStream();

                try {
                    new String();
                    BufferedReader responseReader = new BufferedReader(new InputStreamReader(in1, "UTF-8"));

                    String readLine;
                    while((readLine = responseReader.readLine()) != null) {
                        sb.append(readLine).append("\n");
                    }

                    responseReader.close();
                } catch (Exception var10) {
                    sb.append(var10.getMessage());
                }
            } else {
                sb.append("connect error");
            }
        } catch (Exception var11) {
            StringWriter stringWriter = new StringWriter();
            PrintWriter writer = new PrintWriter(stringWriter);
            var11.printStackTrace(writer);
            StringBuffer buffer = stringWriter.getBuffer();
            sb.append(buffer.toString());
        }

        return sb.toString();
    }

    public static String getJsonData(String urls) {
        try {
            URL url = new URL(urls);
            HttpURLConnection connection = (HttpURLConnection)url.openConnection();
            connection.setConnectTimeout(5000);
            connection.setDoInput(true);
            connection.setRequestMethod("GET");
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
            connection.connect();
            InputStream inputStream = connection.getInputStream();
            byte[] data = new byte[1024];
            StringBuffer sb = new StringBuffer();
            boolean var6 = false;

            String message;
            while(inputStream.read(data) != -1) {
                message = new String(data, Charset.forName("utf-8"));
                sb.append(message);
            }

            message = sb.toString();
            inputStream.close();
            connection.disconnect();
            return message;
        } catch (Exception var8) {
            StringWriter stringWriter = new StringWriter();
            PrintWriter writer = new PrintWriter(stringWriter);
            var8.printStackTrace(writer);
            StringBuffer buffer = stringWriter.getBuffer();
            return buffer.toString();
        }
    }
}