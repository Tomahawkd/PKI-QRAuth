/**
 * add validator to the forms, add listener for login and register event
 */
$(document).ready(function () {
    initialize();
    /**
     * set the display location of error message.
     */
    $.validator.setDefaults({
        debug: false,
        errorElement: 'div',
        errorPlacement: function (error) {
            $('.error_box').empty();
            $('.error_box').append(error);
        }
    });

    /**
     * the validation rules for login
     */
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
            return false;
        }
    });

    /**
     * implements the login event
     */
    $("#login_btn").click(function () {
        if (!$("#login_form").valid()) {
            return;
        }
        var formObject = {};
        var formArray = $("#login_form").serializeArray();
        $.each(formArray, function (i, item) {
            formObject[item.name] = item.value;
        });

        var data = generateInitialPackage(formObject);
        $.ajax({
            url: "/user/login",
            type: "post",
            contentType: "application/json; charset=utf-8",
            data: JSON.stringify(data),
            dataType: "json",
            success: function (data) {
                if (data.status == -1) {
                    $(".error_box").text("用户名不存在！");
                } else if (data.status == 0) {
                    if (validateInitialResponsePackage(data)) {
                        $(".error_box").text("登录成功！");
                        window.location.href = "home.html";
                    } else {
                        $(".error_box").text("数据验证失败！");
                    }
                } else if (data.status == 1) {
                    $(".error_box").text("密码错误！");
                }
            },
            error: function (e) {
                alert("错误！！");
            }
        });
    });

    /**
     * the validation rules for register
     */
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
            return false;
        }
    });

    /**
     * implements the register event
     */
    $("#register_btn").click(function () {
        if (!$("#register_form").valid()) {
            return;
        }

        var formObject = {};
        var formArray = $("#register_form").serializeArray();
        $.each(formArray, function (i, item) {
            formObject[item.name] = item.value;
        });
        var package = generateInitialPackage(formObject);
        $.ajax({
            url: "/user/register",
            type: "post",
            contentType: "application/json; charset=utf-8",
            data: JSON.stringify(package),
            dataType: "json",
            success: function (data) {
                if (data.status == -1) {
                    $(".error_box").text("该用户名已存在！");
                } else if (data.status == 0) {
                    $(".error_box").text("注册成功！");
                    window.location.href = "index.html";
                } else if (data.status == 1) {
                    $(".error_box").text("注册失败！");
                }
            },
            error: function (e) {
                alert("错误！！");
            }
        });
    });
});
