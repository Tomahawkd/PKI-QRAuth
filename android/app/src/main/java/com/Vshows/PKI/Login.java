package com.Vshows.PKI;
import android.content.Intent;
import android.media.Image;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.text.TextUtils;
import android.util.Log;
import android.view.View;
import android.view.Window;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.TextView;
import android.widget.Toast;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;

import org.json.JSONException;
import org.json.JSONObject;

import java.net.HttpURLConnection;
import java.net.URL;

public class Login extends AppCompatActivity implements View.OnClickListener  {

    private EditText username;
    private EditText password;
    private TextView register;
    private TextView forget;
    private ImageButton login;
    private ImageButton showBtn;

    private String name ;
    private String psw ;
    String TAG = Register.class.getCanonicalName();

    private JSONObject jsonObject;



    protected void onCreate(Bundle savedInstanceState) {
        this.requestWindowFeature(Window.FEATURE_NO_TITLE);

        super.onCreate(savedInstanceState);
        setContentView(R.layout.login);
        initView();

    }
    private void initView() {
        username = (EditText)findViewById(R.id.username);
        password =(EditText) findViewById(R.id.password);
        register =(TextView)findViewById(R.id.register);
        forget = (TextView) findViewById(R.id.forget);
        forget.setOnClickListener(this);
        login = (ImageButton) findViewById(R.id.loginBtn);
        login.setOnClickListener(this);
        register.setOnClickListener(this);
    }

    @Override
    public void onClick(View v) {
        switch (v.getId()) {
            case R.id.register:
                Intent intent = new Intent(this,Register.class);
                startActivity(intent);
                break;
            case R.id.forget:

                break;
            case R.id.loginBtn:
                name = username.getText().toString();
                psw = password.getText().toString();

                if(TextUtils.isEmpty(name))
                    Toast.makeText(this,"请输入用户名！", Toast.LENGTH_LONG).show();
                else if (TextUtils.isEmpty(psw))
                    Toast.makeText(this,"请输入密码！", Toast.LENGTH_LONG).show();
                else {
                    try {
                        JSONObject jsonObject = new JSONObject();

                        jsonObject.put("username",username);
                        jsonObject.put("password",password);

                        //sendToUserServer(String.valueOf(jsonObject));
                    } catch (JSONException e){
                        e.printStackTrace();
                    }
                    Toast.makeText(this, "登录成功！", Toast.LENGTH_LONG).show();
                    Intent intent2 = new Intent(this,index.class);
                    startActivity(intent2);
                }

                break;
            default:

        }
    }


}
