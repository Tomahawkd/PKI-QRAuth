package com.Vshows.PKI.util;

import android.content.Context;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.v7.widget.RecyclerView;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.TextView;

import com.Vshows.PKI.R;

import java.util.List;

public class TokenListAdapter extends ArrayAdapter {
    private int layoutID;

    public TokenListAdapter(Context context, int layout, List<TokenList> tList){
        super(context,layout,tList);
        layoutID = layout;
    }

    @NonNull
    @Override
    public View getView(int position, @Nullable View convertView, @NonNull ViewGroup parent) {
        TokenList tokenList = (TokenList) getItem(position);
        View view = LayoutInflater.from(getContext()).inflate(layoutID,null);
        RecyclerView.ViewHolder viewHolder;

        TextView ua = (TextView)view.findViewById(R.id.ua);
        TextView token = (TextView)view.findViewById(R.id.token);

        ua.setText(tokenList.getUa());
        token.setText(tokenList.getToken());

        return view;
    }
}
