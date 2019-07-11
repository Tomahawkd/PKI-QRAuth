/**
 * add validator to the forms, add listener for login and register event
 */
$(document).ready(function () {
    if (localStorage.getItem("token") !== null && localStorage.getItem("Kcpub") !== null && localStorage.getItem("Kcpri") !== null) {
        $(".error_box").text("检测到账号信息，即将自动登录");
        initialize2();
        window.location.href = "home.html";
        // setInterval(function() {window.location.href = "home.html";}, 2000);
    } else {
        initialize1();
    }


    var $tab_li = $('#login_tab ul li');
    $tab_li.click(function () {
        $(this).addClass('selected').siblings().removeClass('selected');
        var index = $tab_li.index(this);
        $('div.tab_box > div').eq(index).show().siblings().hide();
    });

    $('#login_with_qrcode').click(function () {
        QRAuthentation("/server/qr/gener", "/server/qr/roll", "home.html", $('#qrcode'));
        $("#login_with_password").click(function () {
            if ($("#login_with_qrcode").hasClass("selected")) clearPolling();
        });
    });

    $('#go_to_register').click(function () {
        $('#login_tab').addClass('hide');
        $('#register_tab').removeClass('hide');
    });

    /**
     * set the display location of error message.
     */
    $.validator.setDefaults({
        debug: false,
        errorElement: 'div',
        errorPlacement: function (error) {
            $('.error_box').text(error);
        }
    });

    /**
     * the validation rules for login
     */
    $('#login_form').validate({
        rules: {
            username: {
                required: true,
                rangelength: [6, 18]
            },

            password: {
                required: true,
                rangelength: [6, 18]
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
        $(".error_box").empty();
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
                var msg = JSON.parse(data.M);
                if (msg) {
                    if (msg.status === 0) {
                        if (validateInitialResponsePackage(data)) {
                            $(".error_box").text("登录成功！");
                            window.location.href = "home.html";
                        }
                    } else if (msg.status === -1) {
                        $(".error_box").text("用户名不存在！");
                    } else if (data.status === -2) {
                        $(".error_box").text("密码错误！");
                    } else if (data.status === -3) {
                        $(".error_box").text("服务器内部错误， 请重试！");
                    } else if (data.status === -4) {
                        $(".error_box").text("登录失败，请重试");
                    }
                }
            },
            error: function (e) {
                $(".error_box").text("连接失败！");
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
        var form = $("#register_form");
        if (!form.valid()) {
            return;
        }
        $(".error_box").empty();

        var formObject = {};
        var formArray = form.serializeArray();
        $.each(formArray, function (i, item) {
            formObject[item.name] = item.value;
        });
        $.ajax({
            url: "/user/register",
            type: "post",
            contentType: "application/json; charset=utf-8",
            data: JSON.stringify(generateInitialPackage(formObject)),
            dataType: "json",
            success: function (data) {
                var msg = JSON.parse(data.M);
                if (msg) {
                    if (msg.status === 0) {
                        if (validateInitialResponsePackage(data)) {
                            $(".error_box").text("注册成功！");
                            window.location.href = "index.html";
                        }
                    } else if (msg.status === -1) {
                        $(".error_box").text("该用户名已存在！");
                    } else if (msg.status === -2) {
                        $(".error_box").text("注册失败！");
                    } else if (msg.status === -3) {
                        $(".error_box").text("服务器内部错误，请重试");
                    } else if (msg.status === -4) {
                        $(".error_box").text("注册失败，请重试");
                    }
                }
            },
            error: function (e) {
                $(".error_box").text("连接失败！");
            }
        });
    });
});
