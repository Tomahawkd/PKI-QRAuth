package com.Vshows.PKI;

import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.view.Window;
import android.widget.Button;
import android.widget.EditText;

public class changepsw extends AppCompatActivity implements View.OnClickListener {
    private String session;

    private Handler handler;

    Button confirm;
    EditText oldPsw,newPsw,againPsw;

    protected void onCreate(Bundle savedInstanceState) {
        this.requestWindowFeature(Window.FEATURE_NO_TITLE);

        super.onCreate(savedInstanceState);
        setContentView(R.layout.changepsw);

        Intent intent = getIntent();
        session = intent.getStringExtra("session");
        Log.d("changepswsession" ,session);

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

    }
}
