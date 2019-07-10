package io.tomahawkd.simpleserver.model;

import com.google.gson.Gson;

public class UserInfoModel {

	private transient int index;
	private String username;
	private String name;
	private int sex;
	private String email;
	private String phone;
	private String bio;
	private String image_path;

	public UserInfoModel(int index,
	                     String name, int sex, String email, String phone, String bio, String image_path) {
		this.index = index;
		this.name = name;
		this.sex = sex;
		this.email = email;
		this.phone = phone;
		this.bio = bio;
		this.image_path = image_path;
	}

	public int getIndex() {
		return index;
	}

	public String getUsername() {
		return username;
	}

	public String getName() {
		return name;
	}

	public int getSex() {
		return sex;
	}

	public String getEmail() {
		return email;
	}

	public String getPhone() {
		return phone;
	}

	public String getBio() {
		return bio;
	}

	public String getImage_path() {
		return image_path;
	}

	public String toString() {
		return new Gson().toJson(this);
	}
}
