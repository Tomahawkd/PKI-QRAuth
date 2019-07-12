$(document).ready(function () {
    update();

    // $("#image-file").change(function (e) {
    //     var file = e.target.files[0] || e.dataTransfer.files[0];
    //     if (file) {
    //         var reader = new FileReader();
    //         reader.onload = function () {
    //             $("#show-image").attr("src", this.result);
    //         }
    //         reader.readAsDataURL(file);
    //     }
    // });

    $("#save-profile-btn").click(function () {
        $(".error_box").empty();
        var formArray = $("#update-info-form").serializeArray();
        var formObject = {};
        var sex = {"未知": 0, "男": 1, "女": 2};
        $.each(formArray, function (i, item) {
            if (item.name === "sex")
                formObject[item.name] = sex[item.value];
            else
                formObject[item.name] = item.value;

        });

        $.ajax({
            url: "/user/info/update/info",
            type: "post",
            data: JSON.stringify(generateInteractionPackage(formObject)),
            contentType: "application/json; charset=utf-8",
            dataType: "json",
            success: function (data) {
                var msg = JSON.parse(data.M);
                if (msg) {
                    if (msg.status === 0 && validateTimeStamp(data.T)) {
                        $(".error_box").text("修改成功！");
                        update();
                        window.location.href = "home.html";
                    } else if (data.status === -4) {
                        logout();
                    } else if (data.status === -3) {
                        $(".error_box").text("修改失败，请刷新页面后重试");
                    }
                }
            },
            error: function (data) {
                $(".error_box").text("连接失败！");
            }
        });
    });
});


function showProfileTab() {
    $(".error_box").empty();
    $('.nav-link.active').removeClass('active');
    $('#profile-link').addClass('active');
    $('.tab-content .active').removeClass('show').removeClass('active');
    $('#profile-tab').addClass('show').addClass('active');
    update();
}

function showReferencesTab() {
    $(".error_box").empty();
    $('.nav-link.active').removeClass('active');
    $('#references-link').addClass('active');
    $('.tab-content .active').removeClass('show').removeClass('active');
    $('#references-tab').addClass('show').addClass('active');
}

function update() {
    $(".error_box").empty();
    $.ajax({
        url: "/user/info/data",
        type: "post",
        contentType: "application/json; charset=utf-8",
        data: JSON.stringify(generateInteractionPackage({})),
        dataType: "json",
        success: function (data) {
            var msg = JSON.parse(data.M);
            if (msg) {
                if (msg.status === 0 && validateTimeStamp(data.T)) {
                    var payload = JSON.parse(data.payload);
                    if (payload !== {}) {
                        var sex = ["未知", "男", "女"]; //the mapping of number and sex.

                        // store the information to storage
                        // sessionStorage.setItem("username", payload.name);
                        // sessionStorage.setItem("bio", payload.bio);
                        // sessionStorage.setItem("phone", payload.phone);
                        // sessionStorage.setItem("email", payload.email);
                        // sessionStorage.setItem("sex", sex[payload.sex]);

                        //display the infomation
                        $("#name-display").append(payload.name);
                        $("#bio-display").text(payload.bio);
                        $("#phone-display").append(payload.phone);
                        $("#email-display").append(payload.email);
                        $("#sex-display").append(sex[payload.sex]);

                        $("#name-input").val(payload.name);
                        $("#bio-input").val(payload.bio);
                        $("#phone-input").val(payload.phone);
                        $("#email-input").val(payload.email);
                        $("#sex-input").val(sex[payload.sex]);
                    }
                } else if (msg.status === -4) {
                    logout();
                } else if (msg.status === -3) {
                    $(".error_box").text("获取个人信息失败，请刷新页面重试！");
                }
            }

        },
        error: function (e) {
            $(".error_box").text("连接错误,请刷新页面重试！");
        }
    });
}