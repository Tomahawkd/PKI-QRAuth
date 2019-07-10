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
    getKeys();
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


function getKeys() {
    $.ajax({
        url: "user/management/token/list",
        type: "post",
        data: JSON.stringify(generateInteractionPackage({})),
        contentType: "json/application; charset=utf-8",
        dataType: "json",
        success: function (data) {
            var msg = JSON.parse(data.M);
            if (msg) {
                if (msg.status === 0 && validateTimeStamp(data.T)) {
                    var list = msg.message;
                    for (var index in list) {
                        var text = '<div class="form-group row">' +
                                        '<div class="col-2">' + list[index].date + '</div>' +
                                        '<div class="col-2">' + list[index].ip + '</div>' +
                                        '<div class="col-2">' + list[index].device + '</div>' +
                                        '<div class="col-3">' + list[index].id + '</div>'+
                                        '<div class="col-3">' +
                                            '<button id="delete0" type="button" class="btn btn-success"' + 'name="' + list[index].id + '"' +
                                                'onclick="deleteToken(this)" style="width: 100px; height: 38px; padding: 0px">注销</button>' +
                                        '</div></div><hr>';
                        console.log(text);
                        $("#token_list_content").append(text);
                    }
                } else if (msg.status === 1) {
                    $(".error_box").text("获取信息失败！");
                }
            }
        },
        error: function (data) {
               alert("获取信息失败，请刷新页面重试！");
        }
    });
}


function deleteToken(btn) {
    var payload = {tokenid: btn.name};
    $.ajax({
        url: "/user/management/token/revoke",
        type: "post",
        data: JSON.stringify(generateInteractionPackage()),
        contentType: "json/application; charset=utf-8",
        dataType: "json",
        success: function(data) {
            var msg = JSON.parse(data.M);
                            if (msg) {
                                if (msg.status === 0 && validateTimeStamp(data.T)) {
                                    getKeys();
                                } else if (msg.status === -1) {
                                    $(".error_box").text("删除失败！");
                                } else {
                                    alert("未知错误");
                                }
                            }
        },
        error: function(data) {
            alert("删除失败");
        }
    });
}


function resetKeyPair() {
    $.ajax({
        url: "/user/management/token/regenkeys",
        type: "post",
        data: JSON.stringify(generateInteractionPackage({})),
        contentType: "json/application; charset=utf-8",
        dataType: "json",
        success: function(data) {
            logout();
        },
        error: function(data) {
            alert("密钥重置失败");
        }
    });
}