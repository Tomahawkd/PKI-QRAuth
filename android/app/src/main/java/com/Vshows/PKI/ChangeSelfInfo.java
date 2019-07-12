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
import io.tomahawkd.pki.api.client.util.Utils;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class ChangeSelfInfo extends AppCompatActivity implements View.OnClickListener {
    private String ID;

    private Button conformButton;
    private EditText name,sex,phone,mail,sig;

    private Handler handler = null;

    private String nameInfo,phoneInfo,mailInfo,sigInfo,imagePath = "";
    private int sexInfo;

    public static final MediaType JSON = MediaType.parse("application/json; charset=utf-8");

    protected void onCreate(Bundle savedInstanceState) {
        this.requestWindowFeature(Window.FEATURE_NO_TITLE);

        super.onCreate(savedInstanceState);
        setContentView(R.layout.changeinfo);

        Intent intent = getIntent();
        ID = intent.getStringExtra("username");


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

        getCurrentInfo();
    }

    public void onClick(View view){
        switch (view.getId()){
            case R.id.confirm_info:
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
                            byte[] token = Utils.base64Decode(manager.getToken(context,ID));
                            int nonce = manager.getNonce(context,ID);
                            manager.updateNonce(context,ID,nonce+1);

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

                            Map<String,String> result = new HashMap<>();
                            result = gson.fromJson(resultJson,result.getClass());

                            String check = result.get("check");
                            if(check.equals("0")){
                                Looper.prepare();
                                Toast.makeText(getBaseContext(),"修改成功！", Toast.LENGTH_LONG).show();
                                Intent intent = new Intent(context,index.class);
                                intent.putExtra("username",ID);
                                startActivity(intent);
                                Looper.loop();

                            } else {
                                String message = (String) result.get("message");
                                Looper.prepare();
                                Toast.makeText(getBaseContext(),"check: " + check + "\nmessage: " + message, Toast.LENGTH_LONG).show();
                                Intent intent = new Intent(context,Login.class);
                                startActivity(intent);
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
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    Context context = getBaseContext();
                    Connecter connecter = new Connecter();
                    keyManager manager = new keyManager();
                    String ua = SystemUtil.getSystemModel();
                    String url = URLUtil.getSelfInfoURL(context);

                    String Tpub = manager.getTpub(context);
                    String Spub = manager.getSpub(context);
                    String Cpri = manager.getCpri(context,ID);
                    byte[] token = Utils.base64Decode(manager.getToken(context,ID));
                    Log.d("Token:" ,Utils.base64Encode(token));
                    int nonce = manager.getNonce(context,ID);
                    manager.updateNonce(context,ID,nonce+1);
                    String payload = null;


                    PublicKey TPub = StringToPKey.getPublicKey(Tpub);
                    PublicKey SPub = StringToPKey.getPublicKey(Spub);
                    PrivateKey CPri = StringToPKey.getPrivateKey(Cpri);

                    String resultJson = connecter.interactAuthentication(url,payload,TPub,SPub,token,nonce,CPri,ua);

                    Gson gson = new Gson();
                    Map<String,String> result = new HashMap<>();
                    result = gson.fromJson(resultJson,result.getClass());

                    String check = result.get("check");
                    if(check.equals("0")){
                        String data = result.get("data");
                        /**
                         * change UI
                         */
                        Log.d("selfinfo:",data);
                        Map<String,Object> info = new HashMap<>();
                        info = gson.fromJson(data,info.getClass());

                        sexInfo = (int)Math.round(Double.parseDouble(info.get("sex").toString()));
                        nameInfo = (String)info.get("name");
                        mailInfo = (String)info.get("email");
                        phoneInfo = (String)info.get("phone");
                        sigInfo = (String)info.get("bio");
                        imagePath = (String)info.get("image_path");

                        new Thread() {
                            @Override
                            public void run() {
                                handler.post(changeInfoUI);
                            }
                        }.start();
                    } else {
                        String message = result.get("message");
                        Looper.prepare();
                        Toast.makeText(getBaseContext(),"check: " + check + "\nmessage: " + message, Toast.LENGTH_LONG).show();
                        Intent intent = new Intent(context,Login.class);
                        startActivity(intent);
                        Looper.loop();
                    }
                }catch (Exception e){
                    e.printStackTrace();
                    Log.d("getselfinfo",e.getMessage());
                }
            }
        }).start();
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
}
