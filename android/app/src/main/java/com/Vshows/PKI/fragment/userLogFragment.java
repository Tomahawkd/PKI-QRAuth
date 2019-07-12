package com.Vshows.PKI.fragment;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.support.annotation.Nullable;
import android.support.v4.app.Fragment;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ImageButton;
import android.widget.ListView;
import android.widget.Toast;

import com.Vshows.PKI.Check;
import com.Vshows.PKI.Login;
import com.Vshows.PKI.R;
import com.Vshows.PKI.index;
import com.Vshows.PKI.util.StringToPKey;
import com.Vshows.PKI.util.SystemUtil;
import com.Vshows.PKI.util.TokenList;
import com.Vshows.PKI.util.TokenListAdapter;
import com.Vshows.PKI.util.URLUtil;
import com.Vshows.PKI.util.UserLog;
import com.Vshows.PKI.util.UserLogAdapter;
import com.Vshows.PKI.util.keyManager;
import com.Vshows.zxinglibrary.android.CaptureActivity;
import com.Vshows.zxinglibrary.bean.ZxingConfig;
import com.Vshows.zxinglibrary.common.Constant;
import com.google.gson.Gson;
import com.yanzhenjie.permission.Action;
import com.yanzhenjie.permission.AndPermission;
import com.yanzhenjie.permission.Permission;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import io.tomahawkd.pki.api.client.Connecter;
import io.tomahawkd.pki.api.client.util.Utils;

import static android.app.Activity.RESULT_OK;


public class userLogFragment extends Fragment implements View.OnClickListener {
    @Nullable
    ImageButton scanBtn ;
    ListView listView;
    private int REQUEST_CODE_SCAN = 111;

    private String name;
    private Handler handler = null;

    private boolean isFirstLoading = true;

    private static List<UserLog> userLogList = new ArrayList<>();
    @Override
    public View onCreateView(LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment1,container,false);
        userLogList.clear();
        handler = new Handler();

        scanBtn = (ImageButton) view.findViewById(R.id.scan);
        scanBtn.setOnClickListener(this);

        name = getActivity().getIntent().getStringExtra("username");

        listView = (ListView)view.findViewById(R.id.userlogListView);
        init();
        Log.d("loglist",userLogList.toString());


        return view;
    }

//    @Override
//    public void onResume() {
//        super.onResume();
//
//        if (!isFirstLoading) {
//            //如果不是第一次加载，刷新数据
//            updateUI();
//        }
//
//        isFirstLoading = false;
//    }

    public void init(){
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    Context context = getContext();
                    Connecter connecter = new Connecter();
                    keyManager manager = new keyManager();
                    String ua = SystemUtil.getSystemModel();
                    String url = URLUtil.getGetLogURL(context);

                    String Tpub = manager.getTpub(context);
                    String Spub = manager.getSpub(context);
                    String Cpri = manager.getCpri(context,name);
                    byte[] token = Utils.base64Decode(manager.getToken(context,name));
                    int nonce = manager.getNonce(context,name);
                    manager.updateNonce(context,name,nonce+1);

                    PublicKey TPub = StringToPKey.getPublicKey(Tpub);
                    PublicKey SPub = StringToPKey.getPublicKey(Spub);
                    PrivateKey CPri = StringToPKey.getPrivateKey(Cpri);

                    String resultJson = connecter.getLog(url,token,nonce,TPub,SPub,ua,CPri);

                    Gson gson = new Gson();
                    Map<String,Object> result = new HashMap<>();
                    result = gson.fromJson(resultJson,result.getClass());

                    int check = (int) Math.round(Double.parseDouble(result.get("check").toString()));
                    if(check == 0){
                        List<Map<String,String>> logList = new ArrayList<>();
                        logList = (List<Map<String, String>>) result.get("logList");

                        Log.d("logmessage",logList.toString());
                        int n  = logList.size();
                        Log.d("logsize",n + "");
                        for(int i = 0;i<n;i++){
                            Map<String,String> m = logList.get(i);
                            Log.d("mapfor",m.toString());
                            String time = m.get("time");
                            String ip = m.get("ip");
                            String device = m.get("device");
                            String message = m.get("message");

                            userLogList.add(new UserLog(time,ip,device,message));
                            Log.d("logfor",userLogList.toString());
                        }

                        new Thread() {
                            @Override
                            public void run() {
                                handler.post(changeLogList);
                            }
                        }.start();

                    } else {
                        String message = (String) result.get("message");
                        Looper.prepare();
                        Toast.makeText(getContext(),"check: " + check + "\nmessage: " + message, Toast.LENGTH_LONG).show();
                        Looper.loop();
                    }
                }catch (Exception e){
                    e.printStackTrace();
                    Log.d("loginit",e.getMessage());
                }

            }
        }).start();
//        UserLog userLog = new UserLog(1,1,"127.0.0.1","pct-sl00","change password");
//        userLogList.add(userLog);
    }

    Runnable changeLogList = new Runnable() {
        @Override
        public void run() {
            UserLogAdapter adapter = new UserLogAdapter(getContext(),R.layout.user_log_list,userLogList);
            listView.setAdapter(adapter);
        }
    };

    @Override
    public void onClick(View view) {
        switch (view.getId()) {
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
            default:
        }
    }

    public void onActivityResult(int requestCode, int resultCode, final Intent data) {
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
                            String Cpri = manager.getCpri(context,name);
                            byte[] token = Utils.base64Decode(manager.getToken(context,name));
                            int nonce1 = manager.getNonce(context,name);
                            manager.updateNonce(context,name,nonce1+1);
                            String nonce2 = data.getStringExtra(Constant.CODED_CONTENT);

                            PublicKey TPub = StringToPKey.getPublicKey(Tpub);
                            PublicKey SPub = StringToPKey.getPublicKey(Spub);
                            PrivateKey CPri = StringToPKey.getPrivateKey(Cpri);

                            String resultJson = connecter.updateQRStatus(url,token,nonce1,nonce2,TPub,SPub,CPri,ua);

                            Gson gson = new Gson();
                            Map<String,Object> result = new HashMap<>();
                            result = gson.fromJson(resultJson,result.getClass());

                            int check = (int)Math.round(Double.parseDouble(result.get("check").toString()));
                            if(check == 0){
                                Intent intent = new Intent(getActivity(), Check.class);
                                intent.putExtra("Extra", nonce2);
                                intent.putExtra("username", name);
                                startActivity(intent);
                            } else {
                                String message = (String) result.get("message");
                                Looper.prepare();
                                Toast.makeText(getContext(),"check: " + check + "\nmessage: " + message, Toast.LENGTH_LONG).show();
                                Intent intent = new Intent(context, Login.class);
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