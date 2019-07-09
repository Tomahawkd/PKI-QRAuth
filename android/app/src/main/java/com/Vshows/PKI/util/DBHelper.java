package com.Vshows.PKI.util;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

public class DBHelper extends SQLiteOpenHelper {

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

    private Context context;

    public DBHelper(Context context,String name, SQLiteDatabase.CursorFactory factory, int version) {
        super(context, name, factory, version);
        this.context=context;

    }

    @Override
    public void onCreate(SQLiteDatabase sqLiteDatabase) {
        String SERVER_TABLE_CMD = "CREATE TABLE " + SERVER_TABLE
                + "("
                + KTpub +" TEXT,"
                + KSpub +" TEXT"
                + ");" ;

        String CLIENT_TABLE_CMD = "CREATE TABLE " + CLIENT_TABLE
                + "("
                + ID + " TEXT PRIMARY KEY ,"
                + KCpub +" TEXT,"
                + KCpri +" TEXT,"
                + token +" TEXT,"
                + nonce +" INTEGER "
                + ");" ;

        sqLiteDatabase.execSQL(SERVER_TABLE_CMD);
        sqLiteDatabase.execSQL(CLIENT_TABLE_CMD);
    }

    @Override
    public void onUpgrade(SQLiteDatabase sqLiteDatabase, int i, int i1) {

    }
}
