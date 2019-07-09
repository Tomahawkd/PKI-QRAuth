/**
 * Created by Administrator on 2019/7/8.
 */
function showPasswordTab() {
    $('.nav-link.active').removeClass('active');
    $('#update-password-link').addClass('active');
    $('.tab-content .active').removeClass('show').removeClass('active');
    $('#update-password-tab').addClass('show').addClass('active');
}

function showKeysTab() {
    $('.nav-link.active').removeClass('active');
    $('#update-keys-link').addClass('active');
    $('.tab-content .active').removeClass('show').removeClass('active');
    $('#update-keys-tab').addClass('show').addClass('active');
}

$.validator.setDefaults({
    debug: false,
    errorElement: 'div.error_box',
    errorPlacement: function (error) {
        $('.error_box').empty();
        $('.error_box').append(error);
    }
});

$('#update_password_form').validate({
    rules: {
        password: {
            required: true,
            rangelength: [6, 18]
        },

        new_password: {
            required: true,
            rangelength: [6, 18]
        },

        repeat_new_password: {
            required: true,
            equalTo: '#repeat_new_password'
        }
    },

    messages: {
        password: {
            required: '请输入旧密码',
            rangelength: '密码长度必须为6-18个字符'
        },

        new_password: {
            required: '请输入新密码',
            rangelength: '密码长度必须为6-18个字符'
        },

        repeat_new_password: {
            required: '请再次输入密码',
            equalTo: '两次输入的密码不一致，请检查后再次输入'
        }
    },

    submitHandler: function (form) {
        return false;
    }
});

/**
 * implements the update the change password event
 */
$("#update_password_btn").click(function () {
    if (!$("#update_password_form").valid()) {
        return;
    }

    var formObject = {};
    var formArray = $("#update_password_form").serializeArray();
    $.each(formArray, function (i, item) {
        formObject[item.name] = item.value;
    });
    var package = generateInteractionPackage(formObject);
    $.ajax({
        url: "/user/info/update/password",
        type: "post",
        contentType: "application/json; charset=utf-8",
        data: JSON.stringify(package),
        dataType: "json",
        success: function (data) {
            if (data.status == 0) {
                $(".error_box").text("修改成功！");
                $("#update_password").click();
            } else if (data.status == 1) {
                $(".error_box").text("修改失败！");
            }
        },
        error: function (e) {
            alert("错误！！");
        }
    });
});