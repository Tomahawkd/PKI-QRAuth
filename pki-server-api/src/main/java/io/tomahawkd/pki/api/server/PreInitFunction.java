package io.tomahawkd.pki.api.server;

public interface PreInitFunction <P,R> {
    R apply(P payload) throws Exception;
}