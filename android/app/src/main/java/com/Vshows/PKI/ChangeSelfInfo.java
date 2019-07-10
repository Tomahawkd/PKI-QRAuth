package com.Vshows.PKI;

import android.app.AlertDialog;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.view.Window;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.TextView;
import android.widget.Toast;

import com.Vshows.PKI.util.StringToPKey;
import com.Vshows.PKI.util.SystemUtil;
import com.Vshows.PKI.util.URLUtil;
import com.Vshows.PKI.util.keyManager;
import com.google.gson.Gson;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

import io.tomahawkd.pki.api.client.Connecter;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class ChangeSelfInfo extends AppCompatActivity implements View.OnClickListener {
    private String session;
    private String ID;

    private Button conformButton;
    private EditText name,sex,phone,mail,sig;

    private Handler handler = null;

    private String nameInfo,phoneInfo,mailInfo,sigInfo,imagePath;
    private int sexInfo;

    public static final MediaType JSON = MediaType.parse("application/json; charset=utf-8");

    protected void onCreate(Bundle savedInstanceState) {
        this.requestWindowFeature(Window.FEATURE_NO_TITLE);

        super.onCreate(savedInstanceState);
        setContentView(R.layout.changeinfo);

        Intent intent = getIntent();
        session = intent.getStringExtra("session");
        ID = intent.getStringExtra("username");
        //Log.d("changeinfosession" ,session);

        handler = new Handler();
        initView();
    }
    private void initView() {
        conformButton = (Button) findViewById(R.id.confirm_info);
        conformButton.setOnClickListener(this);
        name = findViewById(R.id.usernmae_info);
        sex = findViewById(R.id.sex_info);
        phone = findViewById(R.id.textView10);
        mail = findViewById(R.id.mail_info);
        sig = findViewById(R.id.information_info);

        //getCurrentInfo();
    }

    public void onClick(View view){
        switch (view.getId()){
            case R.id.confirm_info:
//                try{
//                    JSONObject jsonObject = new JSONObject()
//                            .put("name",name.getText().toString())
//                            .put("phone",phone.getText().toString())
//                            .put("email",mail.getText().toString())
//                            .put("bio",sig.getText().toString())
//                            .put("image_path",imagePath);
//                    if(sex.getText().toString().equals("男"))
//                        jsonObject.put("sex",1);
//                    else if (sex.getText().toString().equals("女"))
//                        jsonObject.put("sex",2);
//                    else
//                        jsonObject.put("sex",0);
//                    //String strBase64 = Base64.encodeToString(jsonObject.toString().getBytes(), Base64.DEFAULT);
//                    //base64解码
//                    //String str2 = new String(Base64.decode(strBase64.getBytes(), Base64.DEFAULT));
//
//                    String url ="http://192.168.43.159/user/info/update/info/";
//                    OkHttpClient client = new OkHttpClient();
//                    RequestBody body = RequestBody.create(JSON,jsonObject.toString());
//                    Log.d("changeinfo","<<<<e="+jsonObject.toString());
//                    final Request request = new Request.Builder()
//                            .addHeader("cookie",session)
//                            .url(url)
//                            .post(body)
//                            .build();
//
//                    Call call = client.newCall(request);
//                    call.enqueue(new Callback() {
//                        public void onFailure(Call call, IOException e) {
//                            Log.d("changeinfoerror","<<<<e="+e);
//                        }
//
//                        @Override
//                        public void onResponse(Call call, Response response) throws IOException {
//                            if(response.isSuccessful()) {
//                                String jsonString = response.body().string();
//                                Log.d("changesuccess","<<<<d="+jsonString);
//                                handle_response(jsonString);
//                            }
//                        }
//                    });
//                }catch (JSONException e){
//                    e.printStackTrace();
//                }
//                //showConfirmDialog();
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            Context context = getBaseContext();
                            Connecter connecter = new Connecter();
                            keyManager manager = new keyManager();
                            String ua = SystemUtil.getSystemModel();
                            String url = URLUtil.getChangeInfoURL(context);

                            String Tpub = manager.getTpub(context);
                            String Spub = manager.getSpub(context);
                            String Cpri = manager.getCpri(context,ID);
                            byte[] token = manager.getToken(context,ID).getBytes();
                            int nonce = manager.getNonce(context,ID);

                            Gson gson = new Gson();
                            Map<String,Object> info = new HashMap<>();
                            info.put("name",name.getText().toString());
                            info.put("phone",phone.getText().toString());
                            info.put("email",mail.getText().toString());
                            info.put("bio",sig.getText().toString());
                            info.put("image_path",imagePath);
                            if(sex.getText().toString().equals("男"))
                                info.put("sex",1);
                            else if (sex.getText().toString().equals("女"))
                                info.put("sex",2);
                            else
                                info.put("sex",0);
                            String payload = gson.toJson(info);

                            PublicKey TPub = StringToPKey.getPublicKey(Tpub);
                            PublicKey SPub = StringToPKey.getPublicKey(Spub);
                            PrivateKey CPri = StringToPKey.getPrivateKey(Cpri);

                            String resultJson = connecter.interactAuthentication(url,payload,TPub,SPub,token,nonce,CPri,ua);

                            Map<String,Object> result = new HashMap<>();
                            result = gson.fromJson(resultJson,result.getClass());

                            int check = (int) result.get("check");
                            if(check == 0){

                            } else {
                                String message = (String) result.get("message");
                                Looper.prepare();
                                Toast.makeText(getBaseContext(),"check: " + check + "\nmessage: " + message, Toast.LENGTH_LONG).show();
                                Looper.loop();
                            }
                        }catch (Exception e){
                            e.printStackTrace();
                            Log.d("loginit",e.getMessage());
                        }

                    }
                }).start();
                break;
            default:
        }
    }

    private void showConfirmDialog(){
        final AlertDialog.Builder confirmDialog = new AlertDialog.Builder(this);

        confirmDialog.setTitle("修改成功");
        confirmDialog.setMessage("已成功为您修改个人信息");
        confirmDialog.show();
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
                        JSONObject mesJson = new JSONObject(jsonString);
                        String json = mesJson.getString("message");
                        JSONObject resultJson = new JSONObject(mesJson.getString("message"));
                        nameInfo = resultJson.getString("name");
                        sexInfo = resultJson.getInt("sex");
                        mailInfo = resultJson.getString("email");
                        phoneInfo = resultJson.getString("phone");
                        sigInfo = resultJson.getString("bio");
                        imagePath = resultJson.getString("image_path");


                        new Thread() {
                            @Override
                            public void run() {
                                super.run();
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

    public void handle_response(String response){
        //String responses = new String(Base64.decode(response.getBytes(), Base64.DEFAULT));
        JSONObject result = null;
        try {
            result = new JSONObject(response);
            int status = (int) result.get("status");
            if(status==-1){
                //子线程使用looper加入队列
                Looper.prepare();
                Toast.makeText(this,"该账户已被使用！", Toast.LENGTH_LONG).show();
                Looper.loop();
            }
            else if(status==0){
                Looper.prepare();
                Toast.makeText(this,"修改成功！", Toast.LENGTH_LONG).show();

                Intent intent1 = new Intent(this,index.class);
                intent1.putExtra("session",session);
                startActivity(intent1);
                Looper.loop();
            }
            else if(status==1){
                Looper.prepare();
                Toast.makeText(this,"！", Toast.LENGTH_LONG).show();
                Looper.loop();
            }
            else {
                Looper.prepare();
                Toast.makeText(this,"网络出现错误，请稍后重试！", Toast.LENGTH_LONG).show();
                Looper.loop();
            }

        } catch (JSONException e) {
            e.printStackTrace();
        }
        //取数据
    }
}
