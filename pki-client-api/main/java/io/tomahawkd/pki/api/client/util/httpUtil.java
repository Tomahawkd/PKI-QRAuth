package io.tomahawkd.pki.api.client.util;
import com.google.gson.Gson;
import com.google.gson.JsonObject;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;

public class httpUtil {
    public static String getJsonData(String jsonObject,String urls){
        StringBuffer sb=new StringBuffer();
        try {
             // 创建url资源  
            URL url = new URL(urls);
             // 建立http连接  
             HttpURLConnection conn = (HttpURLConnection) url.openConnection();
             // 设置允许输出  
             conn.setDoOutput(true);
            // 设置允许输入  
             conn.setDoInput(true);
            // 设置不用缓存  
            conn.setUseCaches(false);

            conn.setConnectTimeout(3000);
            conn.setReadTimeout(3000);
            // 设置传递方式  
            conn.setRequestMethod("POST");
            // 设置维持长连接  
            conn.setRequestProperty("Connection", "Keep-Alive");
            // 设置文件字符集:  
            conn.setRequestProperty("Charset", "UTF-8");
            // 转换为字节数组  
            byte[] data = (jsonObject.getBytes());
             // 设置文件长度  
            conn.setRequestProperty("Content-Length", String.valueOf(data.length));
            // 设置文件类型:  
            conn.setRequestProperty("Content-Type","application/json; charset=UTF-8");
            conn.setRequestProperty("accept","application/json");

            // 开始连接请求  
            conn.connect();

            OutputStream out = new DataOutputStream(conn.getOutputStream()) ;
            // 写入请求的字符串  
            out.write(jsonObject.getBytes());
            out.flush();
            out.close();
             // 请求返回的状态  
             if (HttpURLConnection.HTTP_OK == conn.getResponseCode()){
                // 请求返回的数据  
                InputStream in1 = conn.getInputStream();
                try {
                     String readLine=new String();
                     BufferedReader responseReader=new BufferedReader(new InputStreamReader(in1,"UTF-8"));
                     while((readLine=responseReader.readLine())!=null){
                        sb.append(readLine).append("\n");
                     }
                     responseReader.close();
                } catch (Exception e1) {
                    sb.append(e1.getMessage());
                }
             } else {
                 sb.append("connect error");
             }
        } catch (Exception e) {
            StringWriter stringWriter= new StringWriter();
            PrintWriter writer= new PrintWriter(stringWriter);
            e.printStackTrace(writer);
            StringBuffer buffer= stringWriter.getBuffer();
            sb.append(buffer.toString());
        } finally {
            sb.append("connect finally");
        }

        return sb.toString();
    }
}
