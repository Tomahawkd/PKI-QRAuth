/**
 * Created by Administrator on 2019/6/22.
 */
$(document).ready(function () {
    $('.content-inner').load('profile.html');
    $('#header').css('background-color', 'green');
    $('.page-content').css('min-height', '100%');
    $('html').css('height', '100%');
    $('body').css('height', '100%');

    $.ajax({
        url: "/user/info/data",
        type: "post",
        contentType: "application/json; charset=utf-8",
        data: JSON.stringify(generateInteractionPackage({})),
        dataType: "json",
        success: function (data) {
            alert("成功！");
            $("#name-display").append(data.name);
            $("#name-input").val(data.name);
            $("#bio-display").text(data.bio);
            $("#bio-input").val(data.bio);
            $("#phone-display").append(data.phone);
            $("#phone-input").val(data.phone);
            $("#email-display").append(data.email);
            $("#email-input").val(data.email);
            switch (data.sex) {
                case 1:
                    $("#sex-display").append("女");
                    $("#sex-input").val("女");
                    break;
                case 2:
                    $("#sex-display").append("男");
                    $("#sex-input").val("男");
                    break;
                default:
                    $("#sex-display").append("未知");
                    $("#sex-input").val("未知");
            }
            console.log(data.image);
        },
        error: function (e) {
            alert("错误！");
        }
    });

    $('#profile-menu-item').click(function () {
        $('.side-navbar li.active').removeClass('active');
        $('#profile-menu-item').addClass('active');
        $('.content-inner').load('profile.html');
    });

    $('#security-menu-item').click(function () {
        $('.side-navbar li.active').removeClass('active');
        $('#security-menu-item').addClass('active');
        $('.content-inner').load('security.html');
    });

    $('#log-menu-item').click(function () {
        $('.side-navbar li.active').removeClass('active');
        $('#log-menu-item').addClass('active');
        $('.content-inner').load('log.html');
    });
});
