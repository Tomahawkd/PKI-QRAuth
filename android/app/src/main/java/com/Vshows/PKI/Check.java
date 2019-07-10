package com.Vshows.PKI;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.os.Looper;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.view.Window;
import android.widget.Button;
import android.widget.Toast;

import com.Vshows.PKI.util.StringToPKey;
import com.Vshows.PKI.util.SystemUtil;
import com.Vshows.PKI.util.URLUtil;
import com.Vshows.PKI.util.keyManager;
import com.google.gson.Gson;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

import io.tomahawkd.pki.api.client.Connecter;

public class Check extends AppCompatActivity implements View.OnClickListener{
    private Button checkBtn;
    private Button cancelBtn;
    private String nonce2;
    private String name;

    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        this.requestWindowFeature(Window.FEATURE_NO_TITLE);

        setContentView(R.layout.check);
        initView();
    }

    private void initView() {
        checkBtn = findViewById(R.id.checkBtn);
        cancelBtn = findViewById(R.id.cancelBtn);
        checkBtn.setOnClickListener(this);
        cancelBtn.setOnClickListener(this);

        Intent intent = getIntent();
        nonce2 = intent.getStringExtra("Extra");
        name = intent.getStringExtra("username");
    }

    @Override
    public void onClick(View view) {
        switch (view.getId()){
            case R.id.checkBtn:
                Toast.makeText(this, nonce2, Toast.LENGTH_LONG).show();

                break;
            case R.id.cancelBtn:
                Toast.makeText(this, "you type cancel", Toast.LENGTH_LONG).show();
                break;
            default:
        }
    }

    private void confirmToLogin(final int type){
        new Thread(new Runnable() {
            @Override
            public void run() {
                try{
                    Context context = getBaseContext();
                    Connecter connecter = new Connecter();
                    keyManager manager = new keyManager();
                    String ua = SystemUtil.getSystemModel();
                    String url = URLUtil.getScanQRCodeURL(context);

                    String Tpub = manager.getTpub(context);
                    String Spub = manager.getSpub(context);
                    String Cpri = manager.getCpri(context,name);
                    byte[] token = manager.getToken(context,name).getBytes();
                    int nonce1 = manager.getNonce(context,name);

                    PublicKey TPub = StringToPKey.getPublicKey(Tpub);
                    PublicKey SPub = StringToPKey.getPublicKey(Spub);
                    PrivateKey CPri = StringToPKey.getPrivateKey(Cpri);

                    String resultJson = connecter.updateQRStatusConfirm(url,token,nonce1,nonce2,TPub,SPub,CPri,type,ua);

                    Gson gson = new Gson();
                    Map<String,Object> result = new HashMap<>();
                    result = gson.fromJson(resultJson,result.getClass());

                    int check = (int) result.get("check");
                    if (type == 1){
                        if(check == 0){
                            Intent intent = new Intent(getBaseContext(),index.class);
                            intent.putExtra("Extra", nonce2);
                            intent.putExtra("username", name);
                            startActivity(intent);
                        } else {
                            String message = (String) result.get("message");
                            Looper.prepare();
                            Toast.makeText(getBaseContext(),"check: " + check + "\nmessage: " + message, Toast.LENGTH_LONG).show();
                            Looper.loop();
                        }
                    } else {
                        if(check == 0){
                            Intent intent = new Intent(getBaseContext(), index.class);
                            intent.putExtra("Extra", nonce2);
                            intent.putExtra("username", name);
                            startActivity(intent);
                        } else {
                            String message = (String) result.get("message");
                            Looper.prepare();
                            Toast.makeText(getBaseContext(),"check: " + check + "\nmessage: " + message, Toast.LENGTH_LONG).show();
                            Looper.loop();
                        }
                    }

                }catch (Exception e){
                    e.printStackTrace();
                    Log.d("confirmToLogin",e.getMessage());
                }
            }
        }).start();
    }
}
