//
// Created by Vshows on 2019/7/9.
//

//
// Created by Vshows on 2019/7/9.
//
#include "com_Vshows_PKI_util_JniUtils.h"
#include <string.h>

static jclass contextClass;
static jclass signatureClass;
static jclass packageNameClass;
static jclass packageInfoClass;

const char keyValue[] = {
        21, 25, 21, -45, 25, 98, -55, -45, 10, 35, -45, 35,
        26, -5, 25, -65, -78, -99, 85, 45, -5, 10, -0, 11,
        -35, -48, -98, 65, -32, 14, -67, 25
};

const char iv[] =  {    //16 bit
        -33, 32, -25, 25, 35, -27, 55, -12, -15,32,
        23, 45, -26, 32, 5,16
};


jbyteArray Java_com_Vshows_PKI_util_JniUtils_getKeyValue(JNIEnv *env, jobject obj)
{

    jbyteArray kvArray = (*env)->NewByteArray(env, sizeof(keyValue));
    jbyte *bytes = (*env)->GetByteArrayElements(env,kvArray,0);

    int i;
    for (i = 0; i < sizeof(keyValue);i++){
        bytes[i] = (jbyte)keyValue[i];
    }

    (*env)->SetByteArrayRegion(env,kvArray, 0, sizeof(keyValue),bytes);
    (*env)->ReleaseByteArrayElements(env,kvArray,bytes,0);

    return kvArray;
}

//JNIEXPORT JNICALL
jbyteArray Java_com_Vshows_PKI_util_JniUtils_getIv(JNIEnv *env, jobject obj)
{

    jbyteArray ivArray = (*env)->NewByteArray(env, sizeof(iv));
    jbyte *bytes = (*env)->GetByteArrayElements(env,ivArray, 0);

    int i;
    for (i = 0; i < sizeof(iv); i++){
        bytes[i] = (jbyte)iv[i];
    }

    (*env)->SetByteArrayRegion(env,ivArray, 0, sizeof(iv), bytes);
    (*env)->ReleaseByteArrayElements(env,ivArray,bytes,0);

    return ivArray;
}






