package io.tomahawkd.pki.service;

public interface UserIndexService {

	int getUserIdByTag(String tag, int system);

	String getUserTagById(int id);
}
