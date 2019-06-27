package com.Vshows.PKI;

import android.util.Log;

import org.json.JSONObject;

import java.io.IOException;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.FormBody;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class connectUtil {
    public static final MediaType JSON = MediaType.parse("application/json; charset=utf-8");
    //final String d = "";

    public connectUtil(){

    }

    public void POST(String json,String url){

        final String d ;

        OkHttpClient client = new OkHttpClient();
        RequestBody requestBody = RequestBody.create(JSON,json);

        final Request request = new Request.Builder()
                .url(url)
                .post(requestBody)
                .build();
        Call call = client.newCall(request);
        call.enqueue(new Callback() {

            public void onFailure(Call call, IOException e) {
                Log.d("error","<<<<e="+e);
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                if(response.isSuccessful()) {
                    String d = response.body().string();

                    Log.d("success","<<<<d="+d);
                }
            }
        });
    }





}
