package com.Vshows.PKI;

<<<<<<< HEAD
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.view.Window;
import android.widget.Button;
=======
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.view.Window;
>>>>>>> 83628212b11b01e5087bd34f356c531ce3060bf0
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.TextView;

<<<<<<< HEAD
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class ChangeSelfInfo extends AppCompatActivity  {
    private String session;

    private Button conformButton;
    private EditText name,sex,phone,mail,sig;

    private Handler handler = null;

    private String nameInfo,phoneInfo,mailInfo,sigInfo;
    private int sexInfo;

=======
public class ChangeSelfInfo extends AppCompatActivity  {
>>>>>>> 83628212b11b01e5087bd34f356c531ce3060bf0
    protected void onCreate(Bundle savedInstanceState) {
        this.requestWindowFeature(Window.FEATURE_NO_TITLE);

        super.onCreate(savedInstanceState);
        setContentView(R.layout.changeinfo);
<<<<<<< HEAD

        Intent intent = getIntent();
        session = intent.getStringExtra("session");
        Log.d("session" ,session);

        handler = new Handler();
        initView();
    }
    private void initView() {
        conformButton = (Button) findViewById(R.id.confirm_info);
        name = findViewById(R.id.usernmae_info);
        sex = findViewById(R.id.sex_info);
        phone = findViewById(R.id.textView10);
        mail = findViewById(R.id.mail_info);
        sig = findViewById(R.id.information_info);

        getCurrentInfo();
    }

    public void getCurrentInfo() {
        String url ="http://192.168.43.159/user/info/data/";

        OkHttpClient client = new OkHttpClient();

        final Request request = new Request.Builder()
                .addHeader("cookie",session)
                .url(url)
                .get()
                .build();

        Call call = client.newCall(request);
        call.enqueue(new Callback() {
            public void onFailure(Call call, IOException e) {
                Log.d("getInfoError","<<<<e="+e);
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                if(response.isSuccessful()) {
                    String jsonString = response.body().string();;

                    try {
                        JSONObject resultJson = new JSONObject(jsonString);
                        //nameInfo = resultJson.getString("username");
                        nameInfo = resultJson.getString("name");
                        sexInfo = resultJson.getInt("sex");
                        mailInfo = resultJson.getString("email");
                        phoneInfo = resultJson.getString("phone");
                        sigInfo = resultJson.getString("bio");
                        //imagepath = resultJson.getString("imagepath");


                        new Thread() {
                            @Override
                            public void run() {
                                //super.run();
                                handler.post(changeInfoUI);
                            }
                        }.start();
                    } catch (JSONException e){
                        e.printStackTrace();
                    }

                    Log.d("getInfoSuccess","<<<<d="+jsonString);
                }
            }
        });
    }

    Runnable changeInfoUI = new Runnable() {
        @Override
        public void run() {
            name.setText(nameInfo);
            if(sexInfo==0)
                sex.setText("性别未知");
            else if (sexInfo==1)
                sex.setText("男");
            else
                sex.setText("女");
            mail.setText(mailInfo);
            phone.setText(phoneInfo);
            sig.setText(sigInfo);
        }
    };
=======
        initView();
    }
    private void initView() {

    }
>>>>>>> 83628212b11b01e5087bd34f356c531ce3060bf0
}
