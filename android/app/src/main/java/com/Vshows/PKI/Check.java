package com.Vshows.PKI;

import android.content.Intent;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.view.Window;
import android.widget.Button;
import android.widget.Toast;

public class Check extends AppCompatActivity implements View.OnClickListener{
    private Button checkBtn;
    private Button cancelBtn;
    private String content;

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
        content = intent.getStringExtra("Extra");


    }

    @Override
    public void onClick(View view) {
        switch (view.getId()){
            case R.id.checkBtn:
                Toast.makeText(this, content, Toast.LENGTH_LONG).show();

                break;
            case R.id.cancelBtn:
                Toast.makeText(this, "you type cancel", Toast.LENGTH_LONG).show();
                break;
            default:
        }
    }
}
