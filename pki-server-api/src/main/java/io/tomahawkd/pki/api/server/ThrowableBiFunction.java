package io.tomahawkd.pki.api.server;

public interface ThrowableBiFunction<P,R> {
    R apply(P payload) throws Exception;
}
