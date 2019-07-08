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

public class UserLogAdapter extends ArrayAdapter {
    private int layoutID;

    public UserLogAdapter(Context context, int layout, List<UserLog> userLogList){
        super(context,layout,userLogList);
        layoutID = layout;
    }

    @NonNull
    @Override
    public View getView(int position, @Nullable View convertView, @NonNull ViewGroup parent) {
        UserLog userLog = (UserLog) getItem(position);
        View view = LayoutInflater.from(getContext()).inflate(layoutID,null);

        TextView userID = (TextView)view.findViewById(R.id.userID);
        TextView systemID = (TextView)view.findViewById(R.id.systemID);
        TextView Ip = (TextView)view.findViewById(R.id.ip);
        TextView device = (TextView)view.findViewById(R.id.device);
        TextView message = (TextView)view.findViewById(R.id.doinfo);

        userID.setText(String.valueOf(userLog.getUserId()));
        systemID.setText(String.valueOf(userLog.getSystemId()));
        Ip.setText(userLog.getIp());
        device.setText(userLog.getDevice());
        message.setText(userLog.getMessage());

        return view;
    }
}
