package com.Vshows.PKI.fragment;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.support.annotation.Nullable;
import android.support.v4.app.Fragment;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ImageButton;
import android.widget.ListView;

import com.Vshows.PKI.Check;
import com.Vshows.PKI.R;
import com.Vshows.PKI.util.StringToPKey;
import com.Vshows.PKI.util.SystemUtil;
import com.Vshows.PKI.util.TokenList;
import com.Vshows.PKI.util.TokenListAdapter;
import com.Vshows.PKI.util.UserLog;
import com.Vshows.PKI.util.UserLogAdapter;
import com.Vshows.PKI.util.keyManager;
import com.Vshows.zxinglibrary.android.CaptureActivity;
import com.Vshows.zxinglibrary.bean.ZxingConfig;
import com.Vshows.zxinglibrary.common.Constant;
import com.yanzhenjie.permission.Action;
import com.yanzhenjie.permission.AndPermission;
import com.yanzhenjie.permission.Permission;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

import io.tomahawkd.pki.api.client.Connecter;

import static android.app.Activity.RESULT_OK;


public class userLogFragment extends Fragment implements View.OnClickListener {
    @Nullable
    ImageButton scanBtn ;
    private int REQUEST_CODE_SCAN = 111;

    private List<UserLog> userLogList = new ArrayList<>();
    @Override
    public View onCreateView(LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment1,container,false);
        scanBtn = (ImageButton) view.findViewById(R.id.scan);
        scanBtn.setOnClickListener(this);

        ListView listView = (ListView)view.findViewById(R.id.userlogListView);
        init();
        UserLogAdapter adapter = new UserLogAdapter(getContext(),R.layout.user_log_list,userLogList);
        listView.setAdapter(adapter);

        return view;
    }

    public void init(){
        UserLog userLog = new UserLog(1,1,"127.0.0.1","pct-sl00","change password");
        userLogList.add(userLog);
    }
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

    public void onActivityResult(int requestCode, int resultCode, Intent data) {
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

//                            String Tpub = manager.getTpub(context,name);
//                            String Spub = manager.getSpub(context,name);
//                            String Cpri = manager.getCpri(context,name);
//                            byte[] token = manager.getToken(context,name).getBytes();
//                            int nonce = manager.getNonce(context,name);

//                            PublicKey TPub = StringToPKey.getPublicKey(Tpub);
//                            PublicKey SPub = StringToPKey.getPublicKey(Spub);
//                            PrivateKey CPri = StringToPKey.getPrivateKey(Cpri);
                        }catch (Exception e){
                            e.printStackTrace();
                            Log.d("scanerror",e.getMessage());
                        }
                    }
                }).start();

                String content = data.getStringExtra(Constant.CODED_CONTENT);
                Intent intent = new Intent(getActivity(), Check.class);
                intent.putExtra("Extra", content);
                startActivity(intent);

            }
        }
    }
}