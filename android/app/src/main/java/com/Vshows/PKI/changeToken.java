package com.Vshows.PKI;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.view.Window;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.Toast;

import com.Vshows.PKI.util.StringToPKey;
import com.Vshows.PKI.util.SystemUtil;
import com.Vshows.PKI.util.TokenList;
import com.Vshows.PKI.util.TokenListAdapter;
import com.Vshows.PKI.util.URLUtil;
import com.Vshows.PKI.util.keyManager;
import com.google.gson.Gson;

import org.json.JSONException;
import org.json.JSONObject;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import io.tomahawkd.pki.api.client.Connecter;

public class changeToken extends AppCompatActivity implements TokenListAdapter.InnerItemOnclickListener {

    private String session;
    private String ID;

    private Handler handler;

    Button confirm;
    EditText oldPsw,newPsw,againPsw;

    private List<TokenList> lists = new ArrayList<>();

    protected void onCreate(Bundle savedInstanceState) {
        this.requestWindowFeature(Window.FEATURE_NO_TITLE);

        super.onCreate(savedInstanceState);
        setContentView(R.layout.changetoken);

        Intent intent = getIntent();
//        session = intent.getStringExtra("session");
        ID = intent.getStringExtra("username");

        ListView listView = (ListView)findViewById(R.id.tokenListView);
        init();
        TokenListAdapter adapter = new TokenListAdapter(this,R.layout.token_list,lists,ID,session);
        adapter.setOnInnerItemOnClickListener(this);
        listView.setAdapter(adapter);

    }

    public void init(){
//        new Thread(new Runnable() {
//            @Override
//            public void run() {
//                try {
//                    Context context = getBaseContext();
//                    Connecter connecter = new Connecter();
//                    keyManager manager = new keyManager();
//                    String ua = SystemUtil.getSystemModel();
//                    String url = URLUtil.getGetTokenListURL(context);
//
//                    String Tpub = manager.getTpub(context);
//                    String Spub = manager.getSpub(context);
//                    String Cpri = manager.getCpri(context,ID);
//                    byte[] token = manager.getToken(context,ID).getBytes();
//                    int nonce = manager.getNonce(context,ID);
//
//
//                    PublicKey TPub = StringToPKey.getPublicKey(Tpub);
//                    PublicKey SPub = StringToPKey.getPublicKey(Spub);
//                    PrivateKey CPri = StringToPKey.getPrivateKey(Cpri);
//
//                    String resultJson = connecter.initTokenList(url,token,nonce,TPub,SPub,ua,CPri);
//
//                    Gson gson = new Gson();
//                    Map<String,Object> result = new HashMap<>();
//                    result = gson.fromJson(resultJson,result.getClass());
//
//                    int check = (int) result.get("check");
//                    if(check == 0){
//
//                    } else {
//                        String message = (String) result.get("message");
//                        Looper.prepare();
//                        Toast.makeText(getBaseContext(),"check: " + check + "\nmessage: " + message, Toast.LENGTH_LONG).show();
//                        Looper.loop();
//                    }
//                }catch (Exception e){
//                    e.printStackTrace();
//                    Log.d("loginit",e.getMessage());
//                }
//
//            }
//        }).start();
        TokenList list1 = new TokenList("ua1","token1");
        lists.add(list1);
        TokenList list2 = new TokenList("ua2","token1");
        lists.add(list2);
        TokenList list3 = new TokenList("ua3","token1");
        lists.add(list3);
        TokenList list4 = new TokenList("ua4","token1");
        lists.add(list4);
        TokenList list5 = new TokenList("ua5","token1");
        lists.add(list5);
    }

    @Override
    public void itemClick(final View v) {
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
//                    Context context = getBaseContext();
//                    Connecter connecter = new Connecter();
//                    keyManager manager = new keyManager();
//                    String ua = SystemUtil.getSystemModel();
//                    String url = URLUtil.getRevokeTokenURL(context);
//
//                    String Tpub = manager.getTpub(context);
//                    String Spub = manager.getSpub(context);
//                    String Cpri = manager.getCpri(context,ID);
//                    byte[] token = manager.getToken(context,ID).getBytes();
//                    int nonce = manager.getNonce(context,ID);
//
//                    PublicKey TPub = StringToPKey.getPublicKey(Tpub);
//                    PublicKey SPub = StringToPKey.getPublicKey(Spub);
//                    PrivateKey CPri = StringToPKey.getPrivateKey(Cpri);
//
//                    String resultJson = connecter.revokeToken(url,token,nonce,TPub,SPub,ua,CPri);
//
//                    Gson gson = new Gson();
//                    Map<String,Object> result = new HashMap<>();
//                    result = gson.fromJson(resultJson,result.getClass());
//
//                    int check = (int) result.get("check");
//                    if(check == 0){
//                        /**
//                         * change UI
//                         */
//                        Intent intent = new Intent(context, changeToken.class);
//                        intent.putExtra("session",session);
//                        intent.putExtra("username",ID);
//                        startActivity(intent);
//                    } else {
//                        String message = (String) result.get("message");
//                        Looper.prepare();
//                        Toast.makeText(getBaseContext(),"check: " + check + "\nmessage: " + message, Toast.LENGTH_LONG).show();
//                        Looper.loop();
//                    }
                    String s = (String)v.getTag();
                    Looper.prepare();
                    Toast.makeText(getBaseContext(),"ua: " + s, Toast.LENGTH_LONG).show();
                    Looper.loop();
                }catch (Exception e){
                    e.printStackTrace();
                }
            }
        }).start();
    }
}
