/**
 * Created by Administrator on 2019/6/24.
 */
$(document).ready(function () {
    $.validator.setDefaults({
        debug: false,
        errorElement: 'div',
        errorPlacement: function (error, element) {
            $('.error_box').empty();
            $('.error_box').append(error);
        }
    });

    $('#login_form').validate({
        rules: {
            username: {
                required: true,
                rangelength: [6, 18],
            },

            password: {
                required: true,
                rangelength: [6, 18],
            }
        },

        messages: {
            username: {
                required: '请输入用户名',
                rangelength: '用户名长度必须为6-18个字符',
            },

            password: {
                required: '请输入密码',
                rangelength: '密码长度必须为6-18个字符',
            }
        },

        submitHandler: function (form) {
            $("#login_form").ajaxSubmit({
                success: function (data) {
                    alert(data);
                    alert("登录成功");
                },

                error: function (data) {
                    alert(data.message);
                }
            });

            return false;
        }
    });

    $('#register_form').validate({
        rules: {
            username: {
                required: true,
                rangelength: [6, 18]
            },

            password: {
                required: true,
                rangelength: [6, 18]
            },

            confirm_password: {
                required: true,
                equalTo: '#register_password_value'
            }
        },

        messages: {
            username: {
                required: '请输入用户名',
                rangelength: '用户名长度必须为6-18个字符'
            },

            password: {
                required: '请输入密码',
                rangelength: '密码长度必须为6-18个字符'
            },

            confirm_password: {
                required: '请再次输入密码',
                equalTo: '两次输入的密码不一致，请检查后再次输入'
            }
        },

        submitHandler: function (form) {
            $("#register_form").ajaxSubmit({
                success: function (data) {
                    alert(data);
                    alert("注册成功");
                },

                error: function (data) {
                    alert(data.message);
                }
            });

            return false;
        }
    })
});