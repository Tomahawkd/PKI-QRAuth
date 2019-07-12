package com.Vshows.PKI.fragment;

import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.support.annotation.Nullable;
import android.support.v4.app.Fragment;
import android.support.v4.content.ContextCompat;
import android.support.v7.app.AlertDialog;
import android.util.Log;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.ImageButton;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import com.Vshows.PKI.ChangeSelfInfo;
import com.Vshows.PKI.Check;
import com.Vshows.PKI.Login;
import com.Vshows.PKI.R;
import com.Vshows.PKI.changeToken;
import com.Vshows.PKI.changepsw;
import com.Vshows.PKI.index;
import com.Vshows.PKI.util.StringToPKey;
import com.Vshows.PKI.util.SystemUtil;
import com.Vshows.PKI.util.URLUtil;
import com.Vshows.PKI.util.keyManager;
import com.Vshows.zxinglibrary.android.CaptureActivity;
import com.Vshows.zxinglibrary.bean.ZxingConfig;
import com.Vshows.zxinglibrary.common.Constant;
import com.google.gson.Gson;
import com.yanzhenjie.permission.Action;
import com.yanzhenjie.permission.AndPermission;
import com.yanzhenjie.permission.Permission;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import io.tomahawkd.pki.api.client.Connecter;
import io.tomahawkd.pki.api.client.util.Utils;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

import static android.app.Activity.RESULT_OK;


public class userInfoFragment extends Fragment implements View.OnClickListener {
    @Nullable
    ImageButton scanBtn ;
    private int REQUEST_CODE_SCAN = 111;
    Button changeSelfInfo ;
    Button changePsw;
    Button quit;
    Button changeKey;
    Button changeToken;
    Button confirmQuit,cancelQuit;
    TextView username_information;
    TextView sig_information;
    TextView username2_information;
    TextView sex_information;
    TextView phone_information;
    TextView mail_information;

    private String ID;
    private Handler handler = null;

    private String username,name,email,phone,bio,imagepath;
    private int sex;

//    private boolean isFirstLoading = true;

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
        quit = (Button) view.findViewById(R.id.quit);
        quit.setOnClickListener(this);
        changeToken = (Button) view.findViewById(R.id.changetoken);
        changeToken.setOnClickListener(this);
        username_information = (TextView)view.findViewById(R.id.username_information);
        username2_information = (TextView)view.findViewById(R.id.username2_information);
        sig_information = (TextView)view.findViewById(R.id.sig_information);
        sex_information = (TextView)view.findViewById(R.id.sex_information);
        phone_information  = (TextView)view.findViewById(R.id.phone_infomation);
        mail_information = (TextView)view.findViewById(R.id.mail_information);

        ID = getActivity().getIntent().getStringExtra("username");

        init_info();

        return view;
    }

//    @Override
//    public void onResume() {
//        super.onResume();
//
//        if (!isFirstLoading) {
//            //如果不是第一次加载，刷新数据
//            init_info();
//        }
//
//        isFirstLoading = false;
//    }

    public void init_info(){

        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    Context context = getContext();
                    Connecter connecter = new Connecter();
                    keyManager manager = new keyManager();
                    String ua = SystemUtil.getSystemModel();
                    String url = URLUtil.getSelfInfoURL(context);

                    String Tpub = manager.getTpub(context);
                    String Spub = manager.getSpub(context);
                    String Cpri = manager.getCpri(context,ID);
                    byte[] token = Utils.base64Decode(manager.getToken(context,ID));
                    Log.d("Token" ,Utils.base64Encode(token));
                    int nonce = manager.getNonce(context,ID);
                    manager.updateNonce(context,ID,nonce+1);
                    String payload = null;


                    PublicKey TPub = StringToPKey.getPublicKey(Tpub);
                    PublicKey SPub = StringToPKey.getPublicKey(Spub);
                    PrivateKey CPri = StringToPKey.getPrivateKey(Cpri);

                    String resultJson = connecter.interactAuthentication(url,payload,TPub,SPub,token,nonce,CPri,ua);

                    Gson gson = new Gson();
                    Map<String,String> result = new HashMap<>();
                    result = gson.fromJson(resultJson,result.getClass());

                    String check = result.get("check");
                    if(check.equals("0")){
                        String data = result.get("data");
                        /**
                         * change UI
                         */
                        Log.d("selfinfo:",data);
                        Map<String,Object> info = new HashMap<>();
                        info = gson.fromJson(data,info.getClass());
                        username = ID;
                        sex = (int)Math.round(Double.parseDouble(info.get("sex").toString()));
                        name = (String)info.get("name");
                        email = (String)info.get("email");
                        phone = (String)info.get("phone");
                        bio = (String)info.get("bio");
                        imagepath = (String)info.get("image_path");

                        new Thread() {
                            @Override
                            public void run() {
                                handler.post(changeInfoUI);
                            }
                        }.start();
                    } else {
                        String message = result.get("message");
                        Looper.prepare();
                        Toast.makeText(getContext(),"check: " + check + "\nmessage: " + message, Toast.LENGTH_LONG).show();
                        Intent intent = new Intent(context,Login.class);
                        startActivity(intent);
                        Looper.loop();
                    }
                }catch (Exception e){
                    e.printStackTrace();
                    Log.d("getselfinfo",e.getMessage());
                }
            }
        }).start();
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
                                Intent intent = new Intent(getActivity(), CaptureActivity.class);
                                ZxingConfig config = new ZxingConfig();
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
                intent3.putExtra("username",ID);
                startActivity(intent3);
                break;
            case R.id.changepsw:
                Intent intent4 = new Intent(getActivity(), changepsw.class);
                intent4.putExtra("username",ID);
                startActivity(intent4);
                break;
            case R.id.quit:
                showAlerDialog();
                break;
            case R.id.changetoken:
                Intent intent5 = new Intent(getActivity(), changeToken.class);
                intent5.putExtra("username",ID);
                startActivity(intent5);
                break;
            default:
        }

    }

//    Runnable reGenKey = new Runnable() {
//        @Override
//        public void run() {
//            try {
//                Context context = getContext();
//                Connecter connecter = new Connecter();
//                keyManager manager = new keyManager();
//                String ua = SystemUtil.getSystemModel();
//                String url = URLUtil.getReGenKeyURL(context);
//
//                String Tpub = manager.getTpub(context);
//                String Spub = manager.getSpub(context);
//                String Cpri = manager.getCpri(context,ID);
//                byte[] token = manager.getToken(context,ID).getBytes();
//                int nonce = manager.getNonce(context,ID);
//                manager.updateNonce(context,ID,nonce+1);
//
//                PublicKey TPub = StringToPKey.getPublicKey(Tpub);
//                PublicKey SPub = StringToPKey.getPublicKey(Spub);
//                PrivateKey CPri = StringToPKey.getPrivateKey(Cpri);
//
//                String resultJson = connecter.regenerateKeys(url,token,nonce,TPub,SPub,ua,CPri);
//
//                Gson gson = new Gson();
//                Map<String,Object> result = new HashMap<>();
//                result = gson.fromJson(resultJson,result.getClass());
//
//                int check = (int) result.get("check");
//                if(check == 0){
//
//                } else {
//                    String message = (String) result.get("message");
//                    Looper.prepare();
//                    Toast.makeText(getContext(),"check: " + check + "\nmessage: " + message, Toast.LENGTH_LONG).show();
//                    Looper.loop();
//                }
//            }catch (Exception e){
//                e.printStackTrace();
//                Log.d("loginit",e.getMessage());
//            }
//        }
//    };

    private void showAlerDialog() {
        final AlertDialog dialog = new AlertDialog.Builder(this.getContext()).create();

        View dialogView = View.inflate(getContext(),R.layout.confirm_to_quit,null);
        dialog.setView(dialogView);
        dialog.show();

        Window window = dialog.getWindow();
        WindowManager.LayoutParams params = window.getAttributes();
        params.height = 480;
        params.width = 850;
        window.setAttributes(params);

        confirmQuit = (Button)dialogView.findViewById(R.id.confirm_quit);
        cancelQuit = (Button)dialogView.findViewById(R.id.not_quit);

        confirmQuit.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Intent intent2 = new Intent(getActivity(), Login.class);
                intent2.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
                intent2.addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);
                startActivity(intent2);
            }
        });
        cancelQuit.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                dialog.dismiss();
            }
        });
    }


    public void onActivityResult(int requestCode, int resultCode,final Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        // 扫描二维码/条码回传
        if (requestCode == REQUEST_CODE_SCAN && resultCode == RESULT_OK) {
            if (data != null) {
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            Context context = getContext();
                            Connecter connecter = new Connecter();
                            keyManager manager = new keyManager();
                            String ua = SystemUtil.getSystemModel();
                            String url = URLUtil.getScanQRCodeURL(context);

                            String Tpub = manager.getTpub(context);
                            String Spub = manager.getSpub(context);
                            String Cpri = manager.getCpri(context,ID);
                            byte[] token = Utils.base64Decode(manager.getToken(context,ID));
                            int nonce1 = manager.getNonce(context,ID);
                            manager.updateNonce(context,ID,nonce1+1);
                            String nonce2 = data.getStringExtra(Constant.CODED_CONTENT);
                            Log.d("scannonce",nonce1 + "");
                            Log.d("scantoken",Utils.base64Encode(token));

                            PublicKey TPub = StringToPKey.getPublicKey(Tpub);
                            PublicKey SPub = StringToPKey.getPublicKey(Spub);
                            PrivateKey CPri = StringToPKey.getPrivateKey(Cpri);

                            String resultJson = connecter.updateQRStatus(url,token,nonce1,nonce2,TPub,SPub,CPri,ua);
                            Gson gson = new Gson();
                            Map<String,Object> result = new HashMap<>();
                            result = gson.fromJson(resultJson,result.getClass());

                            int check = (int)Math.round(Double.parseDouble(result.get("check").toString()));
                            if(check == 0){
                                Log.d("nounce2",nonce2);
                                Intent intent = new Intent(getContext(), Check.class);
                                intent.putExtra("Extra", nonce2);
                                intent.putExtra("username",ID);
                                startActivity(intent);
                            } else {
                                String message = (String) result.get("message");
                                Looper.prepare();
                                Toast.makeText(getContext(),"check: " + check + "\nmessage: " + message, Toast.LENGTH_LONG).show();
                                Intent intent = new Intent(context,Login.class);
                                startActivity(intent);
                                Looper.loop();
                            }
                        }catch (Exception e){
                            e.printStackTrace();
                            Log.d("scanerror",e.getMessage());
                        }
                    }
                }).start();


            }
        }
    }
}