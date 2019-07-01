package io.tomahawkd.pki.service;

public interface UserIndexService {

	int getUserIdByTag(String tag);

	String getUserTagById(int id);
}
