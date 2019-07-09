package io.tomahawkd.pki.api.server;

public interface ThrowableFunction<P,R> {
    R apply(P payload) throws Exception;
}