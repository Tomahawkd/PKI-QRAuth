package com.Vshows.PKI.fragment;

import android.content.Intent;
import android.os.Bundle;
import android.support.annotation.Nullable;
import android.support.v4.app.Fragment;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ImageButton;

import com.Vshows.PKI.ChangeSelfInfo;
import com.Vshows.PKI.Check;
import com.Vshows.PKI.Login;
import com.Vshows.PKI.R;
import com.Vshows.PKI.index;
import com.Vshows.zxinglibrary.android.CaptureActivity;
import com.Vshows.zxinglibrary.bean.ZxingConfig;
import com.Vshows.zxinglibrary.common.Constant;
import com.yanzhenjie.permission.Action;
import com.yanzhenjie.permission.AndPermission;
import com.yanzhenjie.permission.Permission;

import java.util.List;

import static android.app.Activity.RESULT_OK;


public class fragment3 extends Fragment implements View.OnClickListener {
    @Nullable
    ImageButton scanBtn ;
    private int REQUEST_CODE_SCAN = 111;
    Button changeSelfInfo ;
    Button changePsw;
    Button quit;
    Button changeKey;
    @Override
    public View onCreateView(LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        View view=inflater.inflate(R.layout.infomation,container,false);
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
        return view;
    }

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
                startActivity(intent3);
                break;
            case R.id.changepsw:
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