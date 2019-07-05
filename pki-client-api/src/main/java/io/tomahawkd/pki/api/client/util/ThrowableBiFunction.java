package io.tomahawkd.pki.util;

@FunctionalInterface
public interface ThrowableBiFunction<T,U,R> {

	R invoke(T t, U u) throws Exception;
}
