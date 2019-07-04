package com.Vshows.PKI.fragment;

import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.support.annotation.Nullable;
import android.support.v4.app.Fragment;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ImageButton;
import android.widget.TextView;

import com.Vshows.PKI.ChangeSelfInfo;
import com.Vshows.PKI.Check;
import com.Vshows.PKI.Login;
import com.Vshows.PKI.R;
import com.Vshows.PKI.changepsw;
import com.Vshows.PKI.index;
import com.Vshows.zxinglibrary.android.CaptureActivity;
import com.Vshows.zxinglibrary.bean.ZxingConfig;
import com.Vshows.zxinglibrary.common.Constant;
import com.yanzhenjie.permission.Action;
import com.yanzhenjie.permission.AndPermission;
import com.yanzhenjie.permission.Permission;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.util.List;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

import static android.app.Activity.RESULT_OK;


public class fragment3 extends Fragment implements View.OnClickListener {
    @Nullable
    ImageButton scanBtn ;
    private int REQUEST_CODE_SCAN = 111;
    Button changeSelfInfo ;
    Button changePsw;
    Button quit;
    Button changeKey;
    TextView username_information;
    TextView sig_information;
    TextView username2_information;
    TextView sex_information;
    TextView phone_information;
    TextView mail_information;

    private String session;
    private Handler handler = null;

    private String username,name,email,phone,bio,imagepath;
    private int sex;

    public static final MediaType JSON = MediaType.parse("application/json; charset=utf-8");
    @Override
    public View onCreateView(LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        View view=inflater.inflate(R.layout.infomation,container,false);

        handler = new Handler();

        scanBtn = (ImageButton) view.findViewById(R.id.scan);
        scanBtn.setOnClickListener(this);
        changeSelfInfo = (Button) view.findViewById(R.id.changeinfo);
        changeSelfInfo.setOnClickListener(this);
        changePsw = (Button) view.findViewById(R.id.changepsw);
        changePsw.setOnClickListener(this);
        changeKey = (Button) view.findViewById(R.id.changekey);
        changeKey.setOnClickListener(this);
        quit = (Button) view.findViewById(R.id.quit);
        quit.setOnClickListener(this);
        username_information = (TextView)view.findViewById(R.id.username_information);
        username2_information = (TextView)view.findViewById(R.id.username2_information);
        sig_information = (TextView)view.findViewById(R.id.sig_information);
        sex_information = (TextView)view.findViewById(R.id.sex_information);
        phone_information  = (TextView)view.findViewById(R.id.phone_infomation);
        mail_information = (TextView)view.findViewById(R.id.mail_information);

        session = getActivity().getIntent().getStringExtra("session");

        //Log.d("sessin" ,session);

        //init_info();

        return view;
    }

    public void init_info(){
        String url ="http://192.168.43.159/user/info/data/";

        OkHttpClient client = new OkHttpClient();

        final Request request = new Request.Builder()
                .addHeader("cookie",session)
                .url(url)
                .get()
                .build();

        Call call = client.newCall(request);
        call.enqueue(new Callback() {
            public void onFailure(Call call, IOException e) {
                Log.d("getInfoError","<<<<e="+e);
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                if(response.isSuccessful()) {
                    String jsonString = response.body().string();
                    try {
                        JSONObject mesJson = new JSONObject(jsonString);
                        String json = mesJson.getString("message");
                        JSONObject resultJson = new JSONObject(mesJson.getString("message"));
                        username = resultJson.getString("username");
                        name = resultJson.getString("name");
                        sex = resultJson.getInt("sex");
                        email = resultJson.getString("email");
                        phone = resultJson.getString("phone");
                        bio = resultJson.getString("bio");
                        //imagepath = resultJson.getString("imagepath");

                        new Thread() {
                            @Override
                            public void run() {
                                //super.run();
                                handler.post(changeInfoUI);
                            }
                        }.start();
                    } catch (JSONException e){
                        e.printStackTrace();
                    }
                }
            }
        });
    }

    Runnable changeInfoUI = new Runnable() {
        @Override
        public void run() {
            username_information.setText(username);
            username2_information.setText(name);
            if(sex==0)
                sex_information.setText("性别未知");
            else if (sex==1)
                sex_information.setText("男");
            else
                sex_information.setText("女");
            mail_information.setText(email);
            phone_information.setText(phone);
            sig_information.setText(bio);
        }
    };

    @Override
    public void onClick(View view) {
        switch (view.getId()){
            case R.id.scan:
                AndPermission.with(this)
                        .permission(Permission.CAMERA, Permission.READ_EXTERNAL_STORAGE)
                        .onGranted(new Action() {
                            @Override
                            public void onAction(List<String> permissions) {
                                Intent intent = new Intent(getActivity(), CaptureActivity.class);                                ZxingConfig config = new ZxingConfig();
                                config.setFullScreenScan(false);
                                intent.putExtra(Constant.INTENT_ZXING_CONFIG, config);
                                startActivityForResult(intent, REQUEST_CODE_SCAN);
                            }
                        })
                        .onDenied(new Action() {
                            @Override
                            public void onAction(List<String> permissions) {
                                //Uri packageURI = Uri.parse("package:" + getPackageName());
                                //Intent intent = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, packageURI);
                                //intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);

                                // startActivity(intent);

                                //Toast.makeText(getActivity(), "权限不足!请设置相关权限", Toast.LENGTH_LONG).show();
                            }
                        }).start();
                break;
            case R.id.changeinfo:
                Intent intent3 = new Intent(getActivity(), ChangeSelfInfo.class);
                intent3.putExtra("session",session);
                startActivity(intent3);
                break;
            case R.id.changepsw:
                Intent intent4 = new Intent(getActivity(), changepsw.class);
                intent4.putExtra("session",session);
                startActivity(intent4);
                break;
            case R.id.quit:
                Intent intent2 = new Intent(getActivity(), Login.class);
                startActivity(intent2);
                break;
            case R.id.changekey:
                break;

            default:
        }

    }

    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        // 扫描二维码/条码回传
        if (requestCode == REQUEST_CODE_SCAN && resultCode == RESULT_OK) {
            if (data != null) {

                String content = data.getStringExtra(Constant.CODED_CONTENT);
                Intent intent = new Intent(getActivity(), Check.class);
                intent.putExtra("Extra", content);
                startActivity(intent);

            }
        }
    }
}