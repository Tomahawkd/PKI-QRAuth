package io.tomahawkd.simpleserver.model;

import com.google.gson.Gson;

public class UserInfoModel {

	private transient int userid;
	private String username;
	private String name;
	private Integer sex;
	private String email;
	private String phone;
	private String bio;
	private String image_path;

	public UserInfoModel(int userid,
	                     String name, Integer sex, String email, String phone, String bio, String image_path) {
		this.userid = userid;
		this.name = name;
		this.sex = sex;
		this.email = email;
		this.phone = phone;
		this.bio = bio;
		this.image_path = image_path;
	}

	public int getIndex() {
		return userid;
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
