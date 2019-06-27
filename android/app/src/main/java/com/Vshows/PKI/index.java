package com.Vshows.PKI;

import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.support.annotation.RequiresApi;
import android.support.v4.app.Fragment;
import android.support.v7.app.AppCompatActivity;
import android.view.Window;

public class index extends AppCompatActivity {
    public String session;
    Fragment fragment = getSupportFragmentManager().findFragmentById(R.id.fl_container);
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        this.requestWindowFeature(Window.FEATURE_NO_TITLE);

        setContentView(R.layout.index);

        Intent intent = getIntent();
        session = intent.getStringExtra("session");
//        Bundle bundle = new Bundle();
//        bundle.putString("session",session);
//        homePageFragment.setArguments(bundle);
        initView();
    }

    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    private void initView() {
        BottomBar bottomBar = findViewById(R.id.bottom_bar);
        bottomBar.setContainer(R.id.fl_container)
                .setTitleBeforeAndAfterColor("#999999", "#ff5d5e")
                .addItem(com.Vshows.PKI.fragment.fragment1.class,
                        "日志",
                        R.mipmap.u25,
                        R.mipmap.u21)
                .addItem(com.Vshows.PKI.fragment.fragment3.class,
                        "我的",
                        R.mipmap.u29,
                        R.mipmap.u33)
                .build();


    }
}
