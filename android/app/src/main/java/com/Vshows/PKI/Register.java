package com.Vshows.PKI;

import android.content.Intent;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.view.Window;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.TextView;
import android.widget.Toast;

public class Register extends AppCompatActivity implements View.OnClickListener {
    private EditText username_r;
    private EditText password_r;
    private EditText re_password_r;
    private ImageButton register_re;
    private TextView forget_re;
    private TextView login_re;
    private jwt jwt = new jwt();
    private String s = jwt.init();





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
        login_re = (TextView) findViewById(R.id.login_re_);
        login_re.setOnClickListener(this);
    }


    @Override
    public void onClick(View view) {
        switch (view.getId()){
            case R.id.registerBtn:
                String password1 = password_r.getText().toString();
                String password2 = re_password_r.getText().toString();
                if(password1.equals(password2)){
                    Toast.makeText(this, s, Toast.LENGTH_LONG).show();
                }
                else {
                    Toast.makeText(this,"s" , Toast.LENGTH_LONG).show();
                    jwt.read(s);
                }
                break;
            case R.id.forget_re:

                break;
            case R.id.login_re_:
                Intent intent1 = new Intent(this,Login.class);
                startActivity(intent1);
                break;
            default:
        }
    }
}
