//
// Created by Vshows on 2019/7/10.
//
#include "com_Vshows_PKI_util_JniUtils.h"
#include <jni.h>
#include <string.h>

const char keyValue[] = {
        21, 25, 21, -45, 25, 98, -55, -45, 10, 35, -45, 35,
        26, -5, 25, -65, -78, -99, 85, 45, -5, 10, -0, 11,
        -35, -48, -98, 65, -32, 14, -67, 25
};

const char iv[] =  {    //16 bit
        -33, 32, -25, 25, 35, -27, 55, -12, -15,32,
        23, 45, -26, 32, 5,16
};

const int RELEASE_SIGN_HASHCODE = -1717205002;

extern "C"
jbyteArray Java_com_Vshows_PKI_util_JniUtils_getKeyValue(JNIEnv *env, jclass jclazz)
{

    jbyteArray kvArray = env->NewByteArray(sizeof(keyValue));
    jbyte *bytes = env->GetByteArrayElements(kvArray,0);

    int i;
    for (i = 0; i < sizeof(keyValue);i++){
        bytes[i] = (jbyte)keyValue[i];
    }

    env->SetByteArrayRegion(kvArray, 0, sizeof(keyValue),bytes);
    env->ReleaseByteArrayElements(kvArray,bytes,0);

    return kvArray;
}

//JNIEXPORT JNICALL
extern "C"
 jbyteArray Java_com_Vshows_PKI_util_JniUtils_getIv(JNIEnv *env, jclass jclazz)
{

    jbyteArray ivArray = env->NewByteArray(sizeof(iv));
    jbyte *bytes = env->GetByteArrayElements(ivArray, 0);

    int i;
    for (i = 0; i < sizeof(iv); i++){
        bytes[i] = (jbyte)iv[i];
    }

    env->SetByteArrayRegion(ivArray, 0, sizeof(iv), bytes);
    env->ReleaseByteArrayElements(ivArray,bytes,0);

    return ivArray;
}

extern "C"
JNIEXPORT jint JNICALL Java_com_Vshows_PKI_util_JniUtils_checkSign
        (JNIEnv *env, jclass jclazz, jobject contextObject){

    jclass native_class = env->GetObjectClass(contextObject);
        jmethodID pm_id = env->GetMethodID(native_class, "getPackageManager", "()Landroid/content/pm/PackageManager;");
        jobject pm_obj = env->CallObjectMethod(contextObject, pm_id);
        jclass pm_clazz = env->GetObjectClass(pm_obj);
        // 得到 getPackageInfo 方法的 ID
        jmethodID package_info_id = env->GetMethodID(pm_clazz, "getPackageInfo","(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
        jclass native_classs = env->GetObjectClass(contextObject);
        jmethodID mId = env->GetMethodID(native_classs, "getPackageName", "()Ljava/lang/String;");
        jstring pkg_str = static_cast<jstring>(env->CallObjectMethod(contextObject, mId));
        // 获得应用包的信息
        jobject pi_obj = env->CallObjectMethod(pm_obj, package_info_id, pkg_str, 64);
        // 获得 PackageInfo 类
        jclass pi_clazz = env->GetObjectClass(pi_obj);
        // 获得签名数组属性的 ID
        jfieldID signatures_fieldId = env->GetFieldID(pi_clazz, "signatures", "[Landroid/content/pm/Signature;");
        jobject signatures_obj = env->GetObjectField(pi_obj, signatures_fieldId);
        jobjectArray signaturesArray = (jobjectArray)signatures_obj;
        jsize size = env->GetArrayLength(signaturesArray);
        jobject signature_obj = env->GetObjectArrayElement(signaturesArray, 0);
        jclass signature_clazz = env->GetObjectClass(signature_obj);


        //第二种方式--检查签名的hashCode的方式

        jmethodID int_hashcode = env->GetMethodID(signature_clazz, "hashCode", "()I");
        jint hashCode = env->CallIntMethod(signature_obj, int_hashcode);
        jint res = 1;
        if(hashCode == RELEASE_SIGN_HASHCODE)
        {
            jint res = 0;
            return res;
        }else{
            return res;
        }


}





