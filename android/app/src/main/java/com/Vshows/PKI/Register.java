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
//    private jwt jwt = new jwt();
//    private String s = jwt.init();





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
//                    try {
////                        JSONObject jsonObject = new JSONObject();
////                        jsonObject.put("username",username);
////                        jsonObject.put("password",password1);
////                        //String strBase64 = Base64.encodeToString(jsonObject.toString().getBytes(), Base64.DEFAULT);
////                        //base64解码
////                        //String str2 = new String(Base64.decode(strBase64.getBytes(), Base64.DEFAULT));
////                        String url ="http://192.168.43.159/user/register";
////
////                        OkHttpClient client = new OkHttpClient();
////                        RequestBody body = RequestBody.create(JSON,jsonObject.toString());
////
////                        final Request request = new Request.Builder()
////                                .url(url)
////                                .post(body)
////                                .build();
////                        Call call = client.newCall(request);
////                        call.enqueue(new Callback() {
////                            public void onFailure(Call call, IOException e) {
////                                Log.d("error","<<<<e="+e);
////                            }
////
////                            @Override
////                            public void onResponse(Call call, Response response) throws IOException {
////                                if(response.isSuccessful()) {
////                                    String jsonString = response.body().string();
////                                    handle_response(jsonString);
////
////                                    Log.d("success","<<<<d="+jsonString);
////                                    //Log.d("success","<<<<status="+status);
////                                }
////                            }
////                        });
////                    } catch (JSONException e){
////                        e.printStackTrace();
////                    }
                    new Thread(new Runnable() {
                        @Override
                        public void run() {
                            try {
                                Context context = getBaseContext();
                                Connecter connecter = new Connecter();
                                keyManager manager = new keyManager();

                                String Tpub = connecter.getAuthenticationServerPublicKey();
                                manager.restoreTpub(context,username,Tpub);

                                String Spub = connecter.getServerPublicKey("1");
                                manager.restoreSpub(context,username,Spub);

                                Gson gson = new Gson();
                                Map<String,Object> result = new HashMap<>();
                                PublicKey TpublicKey = SecurityFunctions.readPublicKey(Tpub);
                                PublicKey SpublicKey = SecurityFunctions.readPublicKey(Spub);
                                String resultJson = connecter.initalizeAuthentication(username,password1,TpublicKey,SpublicKey);
                                result = gson.fromJson(resultJson,result.getClass());

                                String nonce = result.get();
                            }catch (Exception e){
                                e.printStackTrace();
                            }

                        }
                    }).start();
                }
                break;
            case R.id.forget_re:
//                /**
//                 * 可以使用线程池进行优化
//                 */
//                new Thread(new Runnable() {
//                    @Override
//                    public void run() {
//                        Connecter connecter = new Connecter();
//                        String mes = connecter.getServerPublicKey("2");
//                        //String mes = a.a();
//                        Log.d("conntest",mes);
//                        //Toast.makeText(this,"test: " +mes, Toast.LENGTH_LONG).show();
//                    }
//                }).start();


//                try {
//                    SecurityFunctions securityFunctions = new SecurityFunctions();
//                    KeyPair keyPair = securityFunctions.generateKeyPair();
//                    PublicKey publicKey =keyPair.getPublic();
//                    PrivateKey privateKey =   keyPair.getPrivate();
//                    String pu = Utils.base64Encode(publicKey.getEncoded());
//                    String pr = Utils.base64Encode(privateKey.getEncoded());
//                    Log.d("pu","" + publicKey);
//                    Log.d("pr","" + privateKey);
//                    Log.d("pus",pu);
//                    Log.d("prs",pr);
//                    PublicKey a = getPublicKey(pu);
//                    PrivateKey b = getPrivateKey(pr);
//                    Log.d("pu1","" +a);
//                    Log.d("pr1","" + b);
//                    Log.d("pus1",a.toString());
//                    Log.d("prs1",b.toString());
//                } catch (CipherErrorException e){
//                    e.printStackTrace();
//                }

                break;
            case R.id.login_re_:
                Intent intent1 = new Intent(this,Login.class);
                startActivity(intent1);
                break;
            default:
        }
    }

    public static PublicKey getPublicKey(String pu){
        PublicKey a = null;
        try {
            //byte[] bytekey = Base64.decode(pu.getBytes(),Base64.DEFAULT);
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(Utils.base64Decode(pu));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            a = keyFactory.generatePublic(x509EncodedKeySpec);
            //Base64.decode(pu);
        } catch (Exception e){
            e.printStackTrace();
            Log.d("pubkeyerror",e.getMessage());
        }
        return a;
    }
    public static PrivateKey getPrivateKey(String pr){
        PrivateKey a = null;
        try {
            //byte[] bytekey = Base64.decode(pr.getBytes(),Base64.DEFAULT);
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(Utils.base64Decode(pr));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            a =  keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            //Base64.decode(pu);
        } catch (Exception e){
            e.printStackTrace();
            Log.d("prikeyerror",e.getMessage());
        }
        return a;
    }


    public void handle_response(String response){
        //String responses = new String(Base64.decode(response.getBytes(), Base64.DEFAULT));
        JSONObject result = null;
        try {
            result = new JSONObject(response);
            int status = (int) result.get("status");
            if(status==-1){
                Looper.prepare();
                Toast.makeText(this,"该账户已被使用！", Toast.LENGTH_LONG).show();
                Looper.loop();
            }
            else if(status==0){
                Looper.prepare();
                Toast.makeText(this,"注册成功！", Toast.LENGTH_LONG).show();
                Intent intent1 = new Intent(this,Login.class);
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
