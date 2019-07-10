package io.tomahawkd.pki.api.server;


import io.tomahawkd.pki.api.server.util.MalformedJsonException;

public interface ReturnDataFunction<T,R> {
    R apply( T data) throws MalformedJsonException;
}
