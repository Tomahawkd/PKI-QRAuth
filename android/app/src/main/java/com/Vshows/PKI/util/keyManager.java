package com.Vshows.PKI.util;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteOpenHelper;
import android.database.sqlite.SQLiteDatabase;
import android.util.Log;

import java.security.PrivateKey;
import java.security.PublicKey;

public class keyManager {
    private final static String DB_NAME = "keys.db";
    private final static int DB_VERSION = 1;
    public final static String KEY_TABLE = "key_table";
    public final static String ID = "id";
    public  final static String KTpub = "KTpub";
    public final static String KSpub = "KSpub";
    public final static String KCpub = "KCpub";
    public final static String KCpri = "KCpri";
    public final static String nonce = "nonce";
    public final static String token = "token";

    public void restoreSpub(Context context,int id,PublicKey Spub){
        SQLiteOpenHelper dbhelper = new DBHelper(context,DB_NAME,null,DB_VERSION);
        SQLiteDatabase sqLiteDatabase = dbhelper.getWritableDatabase();

        ContentValues contentValues = new ContentValues();
        contentValues.put(ID ,id);
        contentValues.put(KSpub,Spub.toString());

        sqLiteDatabase.insert("key_table",null,contentValues);

    }
    public void restoreTpub(Context context,int id,PublicKey Tpub){
        SQLiteOpenHelper dbhelper = new DBHelper(context,DB_NAME,null,DB_VERSION);
        SQLiteDatabase sqLiteDatabase = dbhelper.getWritableDatabase();

        ContentValues contentValues = new ContentValues();
        contentValues.put(ID ,id);
        contentValues.put(KTpub,Tpub.toString());

        sqLiteDatabase.insert("key_table",null,contentValues);
    }
    public void restoreCkey(Context context,int id,PublicKey Cpub, PrivateKey Cpri){
        SQLiteOpenHelper dbhelper = new DBHelper(context,DB_NAME,null,DB_VERSION);
        SQLiteDatabase sqLiteDatabase = dbhelper.getWritableDatabase();

        ContentValues contentValues = new ContentValues();
        contentValues.put(ID ,id);
        contentValues.put(KCpub ,Cpub.toString());
        contentValues.put(KCpri ,Cpri.toString());

        sqLiteDatabase.insert("key_table",null,contentValues);
    }
    public void restoreToken(Context context,int id,String Token){
        SQLiteOpenHelper dbhelper = new DBHelper(context,DB_NAME,null,DB_VERSION);
        SQLiteDatabase sqLiteDatabase = dbhelper.getWritableDatabase();

        ContentValues contentValues = new ContentValues();
        contentValues.put(ID ,id);
        contentValues.put(token,Token);

        sqLiteDatabase.insert("key_table",null,contentValues);
    }

    public void restoreNonce(Context context,int id,String Nonce){
        SQLiteOpenHelper dbhelper = new DBHelper(context,DB_NAME,null,DB_VERSION);
        SQLiteDatabase sqLiteDatabase = dbhelper.getWritableDatabase();

        ContentValues contentValues = new ContentValues();
        contentValues.put(ID ,id);
        contentValues.put(nonce,Nonce);

        sqLiteDatabase.insert("key_table",null,contentValues);
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
        cursor.close();
    }

}
