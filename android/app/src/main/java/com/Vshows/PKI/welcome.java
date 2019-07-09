package com.Vshows.PKI;

import android.app.AppComponentFactory;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.support.v7.app.AppCompatActivity;
import android.view.Window;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.ImageButton;
import android.widget.ImageView;

public class welcome extends AppCompatActivity {
    private ImageView welcome;
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_FULLSCREEN,
                WindowManager.LayoutParams.FLAG_FULLSCREEN);
        /**标题是属于View的，所以窗口所有的修饰部分被隐藏后标题依然有效,需要去掉标题**/
        requestWindowFeature(Window.FEATURE_NO_TITLE);
        setContentView(R.layout.welcome);
        handler.sendEmptyMessageDelayed(0,3000);
        setContentView(R.layout.welcome);
    }

    public  int getSign(){
        // 通过包管理器获得指定包名包含签名的包信息
        PackageInfo packageInfo  = null;
        try {
            packageInfo = getPackageManager().getPackageInfo(getPackageName(), PackageManager.GET_SIGNATURES);
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
        }
// 通过返回的包信息获得签名数组
        Signature[] signatures = packageInfo.signatures;
//获得应用签名的哈希值
        return signatures[0].hashCode();

    }


    private Handler handler = new Handler() {
        public void handleMessage(Message msg) {
            getHome();
            super.handleMessage(msg);
        }
    };

    public void getHome(){
        Intent intent = new Intent(this, Login.class);
        startActivity(intent);
        finish();
    }
}
