package io.tomahawkd.pki.api.server;


import io.tomahawkd.pki.api.server.util.MalformedJsonException;

public interface ReturnDataFunction<T,P,R> {
    R apply(T data, P userid) throws MalformedJsonException;
}
