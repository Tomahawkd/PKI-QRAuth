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

    private SQLiteDatabase getWritableDB(Context context){
        SQLiteOpenHelper dbhelper = new DBHelper(context,DB_NAME,null,DB_VERSION);
        return dbhelper.getWritableDatabase();
    }

    private SQLiteDatabase getReadableDB(Context context){
        SQLiteOpenHelper dbhelper = new DBHelper(context,DB_NAME,null,DB_VERSION);
        return dbhelper.getReadableDatabase();
    }

    public void restoreSpub(Context context,String id,String Spub){
        SQLiteDatabase sqLiteDatabase = getWritableDB(context);

        ContentValues contentValues = new ContentValues();
        contentValues.put(ID ,id);
        contentValues.put(KSpub,Spub);

        sqLiteDatabase.insert(KEY_TABLE,null,contentValues);

    }
    public void restoreTpub(Context context,String id,String Tpub){
        SQLiteDatabase sqLiteDatabase = getWritableDB(context);

        ContentValues contentValues = new ContentValues();
        contentValues.put(ID ,id);
        contentValues.put(KTpub,Tpub);

        sqLiteDatabase.insert(KEY_TABLE,null,contentValues);
    }
    public void restoreCkey(Context context,String id,String Cpub, String Cpri){
        SQLiteDatabase sqLiteDatabase = getWritableDB(context);

        ContentValues contentValues = new ContentValues();
        contentValues.put(ID ,id);
        contentValues.put(KCpub ,Cpub);
        contentValues.put(KCpri ,Cpri);

        sqLiteDatabase.insert(KEY_TABLE,null,contentValues);
    }
    public void restoreToken(Context context,String id,String Token){
        SQLiteDatabase sqLiteDatabase = getWritableDB(context);

        ContentValues contentValues = new ContentValues();
        contentValues.put(ID ,id);
        contentValues.put(token,Token);

        sqLiteDatabase.insert(KEY_TABLE,null,contentValues);
    }

    public void restoreNonce(Context context,String id,int Nonce){
        SQLiteDatabase sqLiteDatabase = getWritableDB(context);

        ContentValues contentValues = new ContentValues();
        contentValues.put(ID ,id);
        contentValues.put(nonce,Nonce);

        sqLiteDatabase.insert(KEY_TABLE,null,contentValues);
    }

    public String getSpub(Context context,String id){
        SQLiteDatabase sqLiteDatabase = getReadableDB(context);

        Cursor cursor = sqLiteDatabase.query(KEY_TABLE, new String[] { ID,KSpub }, "id=?", new String[] {id }, null, null, null);
        String kspub = "";
        if(cursor.moveToFirst()) {
            kspub = cursor.getString(cursor.getColumnIndex(KSpub));
            Log.d("kspub", kspub);
        } else {
            Log.d("kspuberror","0" );
        }
        cursor.close();
        return kspub;
    }

    public String getTpub(Context context,String id){
        SQLiteDatabase sqLiteDatabase = getReadableDB(context);

        Cursor cursor = sqLiteDatabase.query(KEY_TABLE, new String[] { ID,KTpub }, "id=?", new String[] {id }, null, null, null);
        String ktpub = "";
        if(cursor.moveToFirst()) {
            ktpub = cursor.getString(cursor.getColumnIndex(KTpub));
            Log.d("ktpub", ktpub);
        } else {
            Log.d("ktpuberror","0" );
        }
        cursor.close();
        return ktpub;
    }

    public String getCpub(Context context,String id){
        SQLiteDatabase sqLiteDatabase = getReadableDB(context);

        Cursor cursor = sqLiteDatabase.query(KEY_TABLE, new String[] { ID,KCpub }, "id=?", new String[] {id }, null, null, null);
        String kCpub = "";
        if(cursor.moveToFirst()) {
            kCpub = cursor.getString(cursor.getColumnIndex(KCpub));
            Log.d("kCpub", kCpub);
        } else {
            Log.d("kCpuberror","0" );
        }
        cursor.close();
        return kCpub;
    }

    public String getCpri(Context context,String id){
        SQLiteDatabase sqLiteDatabase = getReadableDB(context);

        Cursor cursor = sqLiteDatabase.query(KEY_TABLE, new String[] { ID,KCpri }, "id=?", new String[] {id }, null, null, null);
        String kCpri = "";
        if(cursor.moveToFirst()) {
            kCpri = cursor.getString(cursor.getColumnIndex(KCpri));
            Log.d("kCpri", kCpri);
        } else {
            Log.d("kCprierror","0" );
        }
        cursor.close();
        return kCpri;
    }

    public String getToken(Context context,String id){
        SQLiteDatabase sqLiteDatabase = getReadableDB(context);

        Cursor cursor = sqLiteDatabase.query(KEY_TABLE, new String[] { ID,token }, "id=?", new String[] {id }, null, null, null);
        String Token = "";
        if(cursor.moveToFirst()) {
            Token = cursor.getString(cursor.getColumnIndex(token));
            Log.d("Token", Token);
        } else {
            Log.d("Tokenerror","0" );
        }
        cursor.close();
        return Token;
    }

    public int getNonce(Context context,String id){
        SQLiteDatabase sqLiteDatabase = getReadableDB(context);

        Cursor cursor = sqLiteDatabase.query(KEY_TABLE, new String[] { ID,nonce }, "id=?", new String[] {id }, null, null, null);
        int Nonce = 0;
        if(cursor.moveToFirst()) {
            Nonce = cursor.getInt(cursor.getColumnIndex(nonce));
            Log.d("Nonce", "Nonce:" + Nonce);
        } else {
            Log.d("Nonceerror","0" );
        }
        cursor.close();
        return Nonce;
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
