/**
 * Created by Administrator on 2019/6/22.
 */
$(document).ready(function () {
    $('.content-inner').load('profile.html');
    $('#header').css('background-color', 'green');
    $('.page-content').css('min-height', '100%');
    $('html').css('height', '100%');
    $('body').css('height', '100%');

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


function logout() {
    $.ajax({
        url: "/user/logout",
        type: "post",
        data: JSON.stringify(generateInteractionPackage({})),
        contentType: "json/applicetion; charset=utf-8",
        dataType: "json"
    });
    sessionStorage.clear();
    localStorage.clear();
    window.location.href = "index.html";
}
