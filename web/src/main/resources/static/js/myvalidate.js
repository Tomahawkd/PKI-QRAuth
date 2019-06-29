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
            return false;
        }
    });

    $("#login_btn").click(function() {
        if(! $("#login_form").valid()) {
            return;
        }
        var formObject = {};
        var formArray =$("#login_form").serializeArray();
        $.each(formArray,function(i,item){
            formObject[item.name] = item.value;
        });
        $.ajax({
            url:"/user/login",
            type:"post",
            contentType: "application/json; charset=utf-8",
            data: JSON.stringify(formObject),
            dataType: "json",
            success:function(data){
                alert(data.message);
            },
            error:function(e){
                alert("错误！！");
            }
        });
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
            return false;
        }
    });

    $("#register_btn").click(function() {
        if(! $("#register_form").valid()) {
            return;
        }
        var formObject = {};
        var formArray =$("#register_form").serializeArray();
        $.each(formArray,function(i,item){
            formObject[item.name] = item.value;
        });
        $.ajax({
            url:"/user/register",
            type:"post",
            contentType: "application/json; charset=utf-8",
            data: JSON.stringify(formObject),
            dataType: "json",
            success:function(data){
                alert(data.message);
            },
            error:function(e){
                alert("错误！！");
            }
        });
    });
});