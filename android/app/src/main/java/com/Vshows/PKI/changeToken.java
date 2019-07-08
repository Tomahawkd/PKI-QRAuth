package com.Vshows.PKI;

import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.view.Window;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ListView;

import com.Vshows.PKI.util.TokenList;
import com.Vshows.PKI.util.TokenListAdapter;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

public class changeToken extends AppCompatActivity {

    private String session;

    private Handler handler;

    Button confirm;
    EditText oldPsw,newPsw,againPsw;

    private List<TokenList> lists = new ArrayList<>();

    protected void onCreate(Bundle savedInstanceState) {
        this.requestWindowFeature(Window.FEATURE_NO_TITLE);

        super.onCreate(savedInstanceState);
        setContentView(R.layout.changetoken);

        ListView listView = (ListView)findViewById(R.id.tokenListView);
        init();
        TokenListAdapter adapter = new TokenListAdapter(this,R.layout.token_list,lists);
        listView.setAdapter(adapter);

    }

    public void init(){
        TokenList list1 = new TokenList("ua1","token1");
        lists.add(list1);
        TokenList list2 = new TokenList("ua1","token1");
        lists.add(list2);
        TokenList list3 = new TokenList("ua1","token1");
        lists.add(list3);
        TokenList list4 = new TokenList("ua1","token1");
        lists.add(list4);
        TokenList list5 = new TokenList("ua1","token1");
        lists.add(list5);
    }
}
