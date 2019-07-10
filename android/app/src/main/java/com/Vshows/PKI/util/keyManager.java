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
    public final static String SERVER_TABLE = "server_table";
    public final static String CLIENT_TABLE = "client_table";
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

    public void restoreServerKey(Context context,String Tpub,String Spub){
        SQLiteDatabase sqLiteDatabase = getWritableDB(context);

        ContentValues contentValues = new ContentValues();
        contentValues.put(KSpub,Spub);
        contentValues.put(KTpub,Tpub);

        sqLiteDatabase.insert(SERVER_TABLE,null,contentValues);
        sqLiteDatabase.close();
    }

    public void restoreClientInfo(Context context,String id,String Cpub,String Cpri,String Token,int Nonce){
        SQLiteDatabase sqLiteDatabase = getWritableDB(context);

        ContentValues contentValues = new ContentValues();
        contentValues.put(ID ,id);
        contentValues.put(KCpub,Cpub);
        contentValues.put(KCpri,Cpri);
        contentValues.put(token,Token);
        contentValues.put(nonce,Nonce);

        sqLiteDatabase.insert(CLIENT_TABLE,null,contentValues);
        sqLiteDatabase.close();
    }

    public String getSpub(Context context){
        SQLiteDatabase sqLiteDatabase = getReadableDB(context);

        Cursor cursor = sqLiteDatabase.query(SERVER_TABLE, new String[] { KSpub }, null,null, null, null, null);
        String kspub = "";
        if(cursor.moveToFirst()) {
            kspub = cursor.getString(cursor.getColumnIndex(KSpub));
            Log.d("kspub", kspub);
        } else {
            Log.d("kspuberror","0" );
        }
        cursor.close();
        sqLiteDatabase.close();
        return kspub;
    }

    public String getTpub(Context context){
        SQLiteDatabase sqLiteDatabase = getReadableDB(context);

        Cursor cursor = sqLiteDatabase.query(SERVER_TABLE, new String[] { KTpub }, null, null, null, null, null);
        String ktpub = "";
        if(cursor.moveToFirst()) {
            ktpub = cursor.getString(cursor.getColumnIndex(KTpub));
            Log.d("ktpub", ktpub);
        } else {
            Log.d("ktpuberror","0" );
        }
        cursor.close();
        sqLiteDatabase.close();
        return ktpub;
    }

    public String getCpub(Context context,String id){
        SQLiteDatabase sqLiteDatabase = getReadableDB(context);

        Cursor cursor = sqLiteDatabase.query(CLIENT_TABLE, new String[] { ID,KCpub }, "id=?", new String[] {id }, null, null, null);
        String kCpub = "";
        if(cursor.moveToFirst()) {
            kCpub = cursor.getString(cursor.getColumnIndex(KCpub));
            Log.d("kCpub", kCpub);
        } else {
            Log.d("kCpuberror","0" );
        }
        cursor.close();
        sqLiteDatabase.close();
        return kCpub;
    }

    public String getCpri(Context context,String id){
        SQLiteDatabase sqLiteDatabase = getReadableDB(context);

        Cursor cursor = sqLiteDatabase.query(CLIENT_TABLE, new String[] { ID,KCpri }, "id=?", new String[] {id }, null, null, null);
        String kCpri = "";
        if(cursor.moveToFirst()) {
            kCpri = cursor.getString(cursor.getColumnIndex(KCpri));
            Log.d("kCpri", kCpri);
        } else {
            Log.d("kCprierror","0" );
        }
        cursor.close();
        sqLiteDatabase.close();
        return kCpri;
    }

    public String getToken(Context context,String id){
        SQLiteDatabase sqLiteDatabase = getReadableDB(context);

        Cursor cursor = sqLiteDatabase.query(CLIENT_TABLE, new String[] { ID,token }, "id=?", new String[] {id }, null, null, null);
        String Token = "";
        if(cursor.moveToFirst()) {
            Token = cursor.getString(cursor.getColumnIndex(token));
            Log.d("Token", Token);
        } else {
            Log.d("Tokenerror","0" );
        }
        cursor.close();
        sqLiteDatabase.close();
        return Token;
    }

    public int getNonce(Context context,String id){
        SQLiteDatabase sqLiteDatabase = getReadableDB(context);

        Cursor cursor = sqLiteDatabase.query(CLIENT_TABLE, new String[] { ID,nonce }, "id=?", new String[] {id }, null, null, null);
        int Nonce = 0;
        if(cursor.moveToFirst()) {
            Nonce = cursor.getInt(cursor.getColumnIndex(nonce));
            Log.d("Nonce", "Nonce:" + Nonce);
        } else {
            Log.d("Nonceerror","0" );
        }
        cursor.close();
        sqLiteDatabase.close();
        return Nonce;
    }

    public void getAllServerKey(Context context){
        SQLiteDatabase sqLiteDatabase = getReadableDB(context);

        Cursor cursor = sqLiteDatabase.query(SERVER_TABLE,null,null,null,null,null,null);
        if(cursor.moveToFirst()) {
            do{
                String Tpub = cursor.getString(cursor.getColumnIndex(KTpub));
                String Spub = cursor.getString(cursor.getColumnIndex(KSpub));

                Log.d("alldata", "\ntpub:" + Tpub + "\nSpub:" + Spub);
            } while (cursor.moveToNext());
        } else {
            Log.d("getAllServerKeyerror","0" );
        }
        cursor.close();
        sqLiteDatabase.close();

    }

    public void getAllInfo(Context context){
        SQLiteDatabase sqLiteDatabase = getReadableDB(context);

        Cursor cursor = sqLiteDatabase.query(CLIENT_TABLE,null,null,null,null,null,null);
        if(cursor.moveToFirst()) {
            do{
                String id = cursor.getString(cursor.getColumnIndex(ID));
                String cpub = cursor.getString(cursor.getColumnIndex(KCpub));
                String cpri = cursor.getString(cursor.getColumnIndex(KCpri));
                String Token = cursor.getString(cursor.getColumnIndex(token));
                int Nonce = cursor.getInt(cursor.getColumnIndex(nonce));

                Log.d("alldata", "\nid:" + id + "\ntoken:" + Token + "\ncpub:" + cpub + "\ncpri:" + cpri + "\nnonce:" + Nonce);
            } while (cursor.moveToNext());
        } else {
            Log.d("getAllInfoerror","0" );
        }
        cursor.close();
        sqLiteDatabase.close();

    }
}
