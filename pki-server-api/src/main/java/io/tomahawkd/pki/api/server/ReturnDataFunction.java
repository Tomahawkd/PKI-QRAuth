package io.tomahawkd.pki.api.server;

public interface ReturnDataFunction<P,T,R> {
    R apply(P message,T data);
}
