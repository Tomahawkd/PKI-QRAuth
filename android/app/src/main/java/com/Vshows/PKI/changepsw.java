package com.Vshows.PKI;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
import android.text.TextUtils;
import android.util.Log;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import com.Vshows.PKI.util.StringToPKey;
import com.Vshows.PKI.util.SystemUtil;
import com.Vshows.PKI.util.URLUtil;
import com.Vshows.PKI.util.keyManager;
import com.google.gson.Gson;

import org.json.JSONException;
import org.json.JSONObject;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

import io.tomahawkd.pki.api.client.Connecter;
import io.tomahawkd.pki.api.client.util.Utils;

public class changepsw extends AppCompatActivity implements View.OnClickListener {
    private String session,ID;


    private Handler handler;

    Button confirm;
    EditText oldPsw,newPsw,againPsw;
    String oPsw,nPsw,aPsw;

    protected void onCreate(Bundle savedInstanceState) {
        this.requestWindowFeature(Window.FEATURE_NO_TITLE);

        super.onCreate(savedInstanceState);
        setContentView(R.layout.changepsw);

        Intent intent = getIntent();
        ID = intent.getStringExtra("username");

        handler = new Handler();
        initView();
    }

    private void initView() {
        confirm = (Button) findViewById(R.id.confirm_psw);
        confirm.setOnClickListener(this);
        oldPsw = (EditText) findViewById(R.id.oldpsw);
        newPsw = (EditText) findViewById(R.id.newpsw);
        againPsw = (EditText) findViewById(R.id.newpswagain);
    }

    @Override
    public void onClick(View view) {
        if(view.getId() == R.id.confirm_psw){
            oPsw = oldPsw.getText().toString();
            nPsw = newPsw.getText().toString();
            aPsw = againPsw.getText().toString();

            if(TextUtils.isEmpty(oPsw))
                Toast.makeText(this,"请输入原密码！", Toast.LENGTH_LONG).show();
            else if (TextUtils.isEmpty(nPsw))
                Toast.makeText(this,"请输入新密码！", Toast.LENGTH_LONG).show();
            else if (TextUtils.isEmpty(aPsw))
                Toast.makeText(this,"请确认新密码！", Toast.LENGTH_LONG).show();
            else if (!TextUtils.equals(nPsw,aPsw))
                Toast.makeText(this, "两次输入的密码不一致，请重新输入！", Toast.LENGTH_LONG).show();
            else{
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            Context context = getBaseContext();
                            Connecter connecter = new Connecter();
                            keyManager manager = new keyManager();
                            String ua = SystemUtil.getSystemModel();
                            String url = URLUtil.getChangePasswordURL(context);

                            String Tpub = manager.getTpub(context);
                            String Spub = manager.getSpub(context);
                            String Cpri = manager.getCpri(context,ID);
                            byte[] token = Utils.base64Decode(manager.getToken(context,ID));
                            int nonce = manager.getNonce(context,ID);
                            manager.updateNonce(context,ID,nonce+1);

                            Gson gson = new Gson();
                            Map<String,String> info = new HashMap<>();
                            info.put("password",oPsw);
                            info.put("new_password",nPsw);
                            String payload = gson.toJson(info);

                            PublicKey TPub = StringToPKey.getPublicKey(Tpub);
                            PublicKey SPub = StringToPKey.getPublicKey(Spub);
                            PrivateKey CPri = StringToPKey.getPrivateKey(Cpri);

                            String resultJson = connecter.interactAuthentication(url,payload,TPub,SPub,token,nonce,CPri,ua);

                            Map<String,Object> result = new HashMap<>();
                            result = gson.fromJson(resultJson,result.getClass());

                            int check = (int) Math.round(Double.parseDouble(result.get("check").toString()));
                            if(check == 0){
                                Intent intent = new Intent(context,Login.class);
                                intent.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
                                intent.addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);
                                startActivity(intent);
                            } else {
                                String message = (String) result.get("message");
                                Looper.prepare();
                                Toast.makeText(getBaseContext(),"check: " + check + "\nmessage: " + message, Toast.LENGTH_LONG).show();
                                Looper.loop();
                            }


                        }catch (Exception e){
                            e.printStackTrace();
                        }
                    }
                }).start();


            }
        }
    }

    private void showFalseDialog() {
        final AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle("修改失败")
                .setMessage("请输入正确的原密码")
                .create();

//        View dialogView = View.inflate(this,R.layout.confirm_to_quit,null);
//        dialog.setView(dialogView);
        dialog.show();

        new Handler().postDelayed(new Runnable() {
            @Override
            public void run() {
                dialog.dismiss();
            }
        }, 1000);


    }

    private void showSuccessDialog() {
        final AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle("修改成功")
                .setMessage("已成功为您修改密码")
                .create();

        dialog.show();

        new Handler().postDelayed(new Runnable() {
            @Override
            public void run() {
                dialog.dismiss();
            }
        }, 2000);

        Intent intent = new Intent(this,index.class);
        startActivity(intent);

    }
}
