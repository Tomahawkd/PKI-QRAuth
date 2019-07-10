$(document).ready(function () {
    $.ajax({
        url: "/user/info/data",
        type: "post",
        contentType: "application/json; charset=utf-8",
        data: JSON.stringify(generateInteractionPackage({})),
        dataType: "json",
        success: function (data) {
            var msg = JSON.parse(data.M);
            if (msg) {
                if (msg.status === 0) {
                    var payload = parseInteractionPackage(data);
                    if (payload !== {}) {
                        alert("成功！");
                        var sex = ["女", "男", "未知"]; //the mapping of number and sex.

                        // store the infomation to storage
                        sessionStorage.setItem("username", data.name);
                        sessionStorage.setItem("bio", data.bio);
                        sessionStorage.setItem("phone", data.phone);
                        sessionStorage.setItem("email", data.email);
                        sessionStorage.setItem("sex", sex[data.sex]);

                        //display the infomation
                        $("#name-display").append(data.name);
                        $("#bio-display").text(data.bio);
                        $("#phone-display").append(data.phone);
                        $("#email-display").append(data.email);
                        $("#sex-display").append(sex[data.sex]);

                        $("#name-input").val(data.name);
                        $("#bio-input").val(data.bio);
                        $("#phone-input").val(data.phone);
                        $("#email-input").val(data.email);
                        $("#sex-input").val(sex[data.sex]);

                        console.log(data.image);
                    }
                } else if (msg.status === 1) {
                    $(".error_box").text("注册失败！");
                }
            }

        },
        error: function (e) {
            alert("错误！");
        }
    });

    $("#image-file").change(function (e) {
        console.log("change image");
        var file = e.target.files[0] || e.dataTransfer.files[0];
        console.log(file);
        if (file) {
            var reader = new FileReader();
            reader.onload = function () {
                $("#show-image").attr("src", this.result);
            }
            reader.readAsDataURL(file);
        }
        console.log("change image finish");
    });

    $("#save-profile-btn").click(function () {
        var formArray = $("#update-info-form").serializeArray();
        var formObject = {};
        $.each(formArray, function (i, item) {
            formObject[item.name] = item.value;
        });

        var sex = ["女", "男", "未知"];
        formObject["sex"] = sex[sex.find(formObject["sex"])];

        $.ajax({
            url: "/user/info/update/info",
            type: "post",
            data: JSON.stringify(generateInteractionPackage(formObject)),
            contentType: "application/json; charset=utf-8",
            processData: false,
            success: function (data) {
                console.log(data);
            },
            error: function (data) {
                console.log(data);
            }
        });
    });
});


function showProfileTab() {
    $('.nav-link.active').removeClass('active');
    $('#profile-link').addClass('active');
    $('.tab-content .active').removeClass('show').removeClass('active');
    $('#profile-tab').addClass('show').addClass('active');
}

function showReferencesTab() {
    $('.nav-link.active').removeClass('active');
    $('#references-link').addClass('active');
    $('.tab-content .active').removeClass('show').removeClass('active');
    $('#references-tab').addClass('show').addClass('active');
}