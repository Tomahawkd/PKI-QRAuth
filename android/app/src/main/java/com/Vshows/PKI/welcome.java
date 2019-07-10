package com.Vshows.PKI;

import android.app.AppComponentFactory;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.provider.Settings;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.Window;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.Toast;

import com.Vshows.PKI.util.SystemUtil;
import com.Vshows.PKI.util.URLUtil;
import com.Vshows.PKI.util.keyManager;
import com.Vshows.PKI.util.JniUtils;

import java.util.Objects;

import io.tomahawkd.pki.api.client.Connecter;

public class welcome extends AppCompatActivity {

    private int getSign() throws PackageManager.NameNotFoundException {
        // 通过包管理器获得指定包名包含签名的包信息
        PackageInfo packageInfo  = getPackageManager().getPackageInfo(getPackageName(), PackageManager.GET_SIGNATURES);
// 通过返回的包信息获得签名数组
        Signature[] signatures = packageInfo.signatures;
//获得应用签名的哈希值
        Log.d("signature",signatures[0].toCharsString());
        Log.d("hashcode", String.valueOf(signatures[0].hashCode()));
        return signatures[0].hashCode();
    }
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_FULLSCREEN,
                WindowManager.LayoutParams.FLAG_FULLSCREEN);
        /**标题是属于View的，所以窗口所有的修饰部分被隐藏后标题依然有效,需要去掉标题**/
        requestWindowFeature(Window.FEATURE_NO_TITLE);
        setContentView(R.layout.welcome);
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {

                }catch (Exception e){
                    e.printStackTrace();
                }
            }
        }).start();
        handler.sendEmptyMessageDelayed(0,3000);




    }


    private Handler handler = new Handler() {
        public void handleMessage(Message msg) {
            getHome(JniUtils.checkSign(welcome.this));
            super.handleMessage(msg);
        }
    };

    public void getHome(int i){
        if(i==0){
            Intent intent = new Intent(this, Login.class);
            startActivity(intent);
            finish();
        }
        else {
            Toast.makeText(this,"验证签名失败，客户端已被修改！！！", Toast.LENGTH_LONG).show();
            finish();

        }

    }
}
