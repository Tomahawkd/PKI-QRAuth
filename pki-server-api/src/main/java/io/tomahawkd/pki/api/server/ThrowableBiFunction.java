package io.tomahawkd.pki.api.server;

public interface ThrowableBiFunction<P,T,R> {
    R apply(P user,T pass) throws Exception;

}
