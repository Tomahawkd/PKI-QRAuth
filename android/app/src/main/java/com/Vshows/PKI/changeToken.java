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
import com.Vshows.PKI.util.UserLog;
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
import io.tomahawkd.pki.api.client.util.Utils;

public class changeToken extends AppCompatActivity {

    private String session;
    private String ID;

    private Handler handler;

    Button confirm;
    EditText oldPsw,newPsw,againPsw;
    ListView listView;
    TokenListAdapter adapter;

    private static List<TokenList> lists = new ArrayList<>();

    protected void onCreate(Bundle savedInstanceState) {
        this.requestWindowFeature(Window.FEATURE_NO_TITLE);
        lists.clear();
        handler = new Handler();

        super.onCreate(savedInstanceState);
        setContentView(R.layout.changetoken);

        Intent intent = getIntent();
        ID = intent.getStringExtra("username");

        listView = (ListView)findViewById(R.id.tokenListView);
        init();


    }

    public void init(){
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    Context context = getBaseContext();
                    Connecter connecter = new Connecter();
                    keyManager manager = new keyManager();
                    String ua = SystemUtil.getSystemModel();
                    String url = URLUtil.getGetTokenListURL(context);

                    String Tpub = manager.getTpub(context);
                    String Spub = manager.getSpub(context);
                    String Cpri = manager.getCpri(context,ID);
                    byte[] token = Utils.base64Decode(manager.getToken(context,ID));
                    int nonce = manager.getNonce(context,ID);
                    manager.updateNonce(context,ID,nonce+1);


                    PublicKey TPub = StringToPKey.getPublicKey(Tpub);
                    PublicKey SPub = StringToPKey.getPublicKey(Spub);
                    PrivateKey CPri = StringToPKey.getPrivateKey(Cpri);

                    String resultJson = connecter.initTokenList(url,token,nonce,TPub,SPub,ua,CPri);

                    Gson gson = new Gson();
                    Map<String,Object> result = new HashMap<>();
                    result = gson.fromJson(resultJson,result.getClass());

                    int check = (int) Math.round(Double.parseDouble(result.get("check").toString()));
                    if(check == 0){
                        List<Map<String,String>> tokenList = new ArrayList<>();
                        tokenList = (List<Map<String, String>>) result.get("tokenList");

                        Log.d("tokenlist",tokenList.toString());
                        int n  = tokenList.size();
                        Log.d("tokenlistnum",n + "");

                        for(int i = 0;i<n;i++){
                            Map<String,String> m = tokenList.get(i);
                            Log.d("mapfor",m.toString());
                            String date = m.get("date");
                            String ip = m.get("ip");
                            String device = m.get("device");
                            String id = m.get("id");

                            lists.add(new TokenList(date,ip,device,id));
                        }

                        new Thread() {
                            @Override
                            public void run() {
                                handler.post(changeTokenList);
                            }
                        }.start();

                    } else {
                        String message = (String) result.get("message");
                        Looper.prepare();
                        Toast.makeText(getBaseContext(),"check: " + check + "\nmessage: " + message, Toast.LENGTH_LONG).show();
                        Looper.loop();
                    }
                }catch (Exception e){
                    e.printStackTrace();
                    Log.d("loginit",e.getMessage());
                }

            }
        }).start();

    }

    Runnable changeTokenList = new Runnable() {
        @Override
        public void run() {
            adapter = new TokenListAdapter(getBaseContext(),R.layout.token_list,lists);
            adapter.setOnInnerItemOnClickListener(new TokenListAdapter.InnerItemOnclickListener() {
                @Override
                public void itemClick(final View v) {
                    new Thread(new Runnable() {
                        @Override
                        public void run() {
                            try {
                                Context context = getBaseContext();
                                Connecter connecter = new Connecter();
                                keyManager manager = new keyManager();
                                String ua = SystemUtil.getSystemModel();
                                String url = URLUtil.getRevokeTokenURL(context);

                                String Tpub = manager.getTpub(context);
                                String Spub = manager.getSpub(context);
                                String Cpri = manager.getCpri(context,ID);
                                byte[] token = Utils.base64Decode(manager.getToken(context,ID));
                                int nonce = manager.getNonce(context,ID);
                                manager.updateNonce(context,ID,nonce+1);

                                PublicKey TPub = StringToPKey.getPublicKey(Tpub);
                                PublicKey SPub = StringToPKey.getPublicKey(Spub);
                                PrivateKey CPri = StringToPKey.getPrivateKey(Cpri);

                                String s = (String)v.getTag();
                                String resultJson = connecter.revokeToken(s,url,token,nonce,TPub,SPub,ua,CPri);

                                Gson gson = new Gson();
                                Map<String,Object> result = new HashMap<>();
                                result = gson.fromJson(resultJson,result.getClass());

                                int check = (int) Math.round(Double.parseDouble(result.get("check").toString()));
                                if(check == 0){
                                    /**
                                     * change UI
                                     */
                                    Intent intent = new Intent(context, changeToken.class);
                                    intent.putExtra("username",ID);
                                    startActivity(intent);
                                } else {
                                    String message = (String) result.get("message");
                                    Looper.prepare();
                                    Toast.makeText(getBaseContext(),"check: " + check + "\nmessage: " + message, Toast.LENGTH_LONG).show();
                                    Looper.loop();
                                }
//                                String s = (String)v.getTag();
//                                Looper.prepare();
//                                Toast.makeText(getBaseContext(),"ua: " + s, Toast.LENGTH_LONG).show();
//                                Looper.loop();
                            }catch (Exception e){
                                e.printStackTrace();
                            }
                        }
                    }).start();
                }
            });
            listView.setAdapter(adapter);
        }
    };
}
