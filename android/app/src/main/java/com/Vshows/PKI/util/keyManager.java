package com.Vshows.PKI.util;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteOpenHelper;
import android.database.sqlite.SQLiteDatabase;
import android.util.Log;

import java.security.PrivateKey;
import java.security.PublicKey;

public class keyManager { ;

    public void restoreSpub(PublicKey Spub){
        //SQLiteOpenHelper dbHelper = new DBHelper(,"keys.db");

    }
    public void restoreTpub(PublicKey Tpub){

    }
    public void restoreCkey(PublicKey Cpub, PrivateKey Cpri){

    }
    public void restoreToken(String Token){

    }

    public void test(Context context,String str){
        SQLiteOpenHelper dbhelper =    new DBHelper(context,"keys.db",null,1);

        SQLiteDatabase sqLiteDatabase = dbhelper.getWritableDatabase();
        SQLiteDatabase sqLiteDatabase1 = dbhelper.getReadableDatabase();

        ContentValues contentValues = new ContentValues();
        contentValues.put("id",1);
        contentValues.put("KTpub",str);

        sqLiteDatabase.insert("key_table",null,contentValues);

        Cursor cursor = sqLiteDatabase1.rawQuery("select * from key_table where id=?",new String[]{"1"});
        if(cursor.moveToFirst()) {
            String ktpub = cursor.getString(cursor.getColumnIndex("KTpub"));
            Log.d("ktpub", ktpub);
        } else {
            Log.d("ktpuberror","0000000000000000000" );
        }
    }

}
