package io.tomahawkd.pki.util;

import java.io.IOException;

@FunctionalInterface
public interface ContextCallback<L, M, N, O, P, R> {

	R invoke(L l, M m, N n, O o, P p) throws RuntimeException, IOException;
}
