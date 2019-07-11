package com.Vshows.PKI;

import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.os.Looper;
import android.support.annotation.RequiresApi;
import android.support.v7.app.AppCompatActivity;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.view.Window;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.TextView;
import android.widget.Toast;


import com.Vshows.PKI.util.SystemUtil;
import com.Vshows.PKI.util.URLUtil;
import com.Vshows.PKI.util.keyManager;
import com.google.gson.Gson;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import io.tomahawkd.pki.api.client.Connecter;
import io.tomahawkd.pki.api.client.exceptions.CipherErrorException;
import io.tomahawkd.pki.api.client.util.SecurityFunctions;
import io.tomahawkd.pki.api.client.util.Utils;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.FormBody;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class Register extends AppCompatActivity implements View.OnClickListener {
    public static final MediaType JSON = MediaType.parse("application/json; charset=utf-8");
    private EditText username_r;
    private EditText password_r;
    private EditText re_password_r;
    private ImageButton register_re;
    private TextView forget_re;
    private TextView login_re;

    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        this.requestWindowFeature(Window.FEATURE_NO_TITLE);

        setContentView(R.layout.register);
        initView();

    }
    private void initView() {
        username_r = (EditText) findViewById(R.id.username_re);
        password_r = (EditText) findViewById(R.id.password_re);
        re_password_r = (EditText) findViewById(R.id.re_password_re) ;
        register_re =(ImageButton)findViewById(R.id.registerBtn);
        register_re.setOnClickListener(this);
        forget_re = (TextView) findViewById(R.id.forget_re);
        forget_re.setOnClickListener(this);
        login_re = (TextView) findViewById(R.id.login_re_);
        login_re.setOnClickListener(this);
    }


    @RequiresApi(api = Build.VERSION_CODES.FROYO)
    @Override
    public void onClick(View view) {
        switch (view.getId()){
            case R.id.registerBtn:
                final String username = username_r.getText().toString();
                final String password1 = password_r.getText().toString();
                String password2 = re_password_r.getText().toString();
                if(TextUtils.isEmpty(username))
                    Toast.makeText(this,"用户名不能为空！", Toast.LENGTH_LONG).show();
                else if (TextUtils.isEmpty(password1))
                    Toast.makeText(this,"密码不能为空！", Toast.LENGTH_LONG).show();
                else if (TextUtils.isEmpty(password2))
                    Toast.makeText(this,"请再次输入密码！", Toast.LENGTH_LONG).show();
                else if (!TextUtils.equals(password1,password2))
                    Toast.makeText(this, "两次输入的密码不一致，请重新输入！", Toast.LENGTH_LONG).show();
                else {
                    new Thread(new Runnable() {
                        @Override
                        public void run() {
                            try {
                                Context context = getBaseContext();
                                Connecter connecter = new Connecter();
                                keyManager manager = new keyManager();
                                String ua = SystemUtil.getSystemModel();
                                String registerURL = URLUtil.getRegisterURL(context);

                                PublicKey TpublicKey = SecurityFunctions.readPublicKey(manager.getTpub(context));
                                PublicKey SpublicKey = SecurityFunctions.readPublicKey(manager.getSpub(context));
//                                PublicKey TpublicKey = SecurityFunctions.generateKeyPair().getPublic();
//                                PublicKey SpublicKey = SecurityFunctions.generateKeyPair().getPublic();

                                String resultJson = connecter.initalizeAuthentication(registerURL,username,password1,TpublicKey,SpublicKey,ua);
                                Log.d("resultjson",resultJson);

                                Gson gson = new Gson();
                                Map<String,Object> result = new HashMap<>();
                                result = gson.fromJson(resultJson,result.getClass());

                                int check = (int)Math.round(Double.parseDouble(result.get("check").toString()));
                                if(check == 0){
                                    int nonce = (int) Math.round(Double.parseDouble(result.get("nonce").toString()));
                                    String token = (String)(result.get("Token"));
                                    String Cpub = (String) result.get("Cpub");
                                    String Cpri = (String) result.get("Cpri");

                                    manager.restoreClientInfo(context,username,Cpub,Cpri,token,nonce);

                                    Intent intent = new Intent(context,Login.class);
                                    startActivity(intent);
                                } else {
                                    String message = (String) result.get("message");
                                    Looper.prepare();
                                    Toast.makeText(getBaseContext(),"message: " + message, Toast.LENGTH_LONG).show();
                                    Looper.loop();
                                }
                            }catch (Exception e){
                                e.printStackTrace();
                                Log.d("initerror",e.getMessage());
                            }

                        }
                    }).start();
                }
                break;
            case R.id.forget_re:
                Context context = this;
                keyManager manager = new keyManager();
                manager.getAllServerKey(context);
                manager.getAllInfo(context);
                break;
            case R.id.login_re_:
                Intent intent1 = new Intent(this,Login.class);
                startActivity(intent1);
                break;
            default:
        }
    }
}
