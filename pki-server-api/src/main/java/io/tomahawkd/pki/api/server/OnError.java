package io.tomahawkd.pki.api.server;

//注册失败，删除用户
public interface OnError {
    void delete(int index);
}
