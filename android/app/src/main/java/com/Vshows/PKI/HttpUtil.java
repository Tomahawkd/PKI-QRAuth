package com.Vshows.PKI;


import org.json.JSONObject;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;


/**
 * Created by 舞动的心 on 2018/3/4.
 */

public class HttpUtil {

    public Register register;

    //使用Get方式获取服务器上数据
    public static void sendOkHttpRequest(final String address, final okhttp3.Callback callback) {
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
                .url(address)
                .build();
        client.newCall(request).enqueue(callback);
    }

    //使用Post方式向服务器上提交数据并获取返回提示数据
    public static void sendOkHttpResponse(String address, final RequestBody requestBody, final okhttp3.Callback callback) {
        OkHttpClient client = new OkHttpClient();
//        JSONObject object;
        Request request = new Request.Builder()
                .url(address).post(requestBody).build();
        client.newCall(request).enqueue(callback);
    }


}
