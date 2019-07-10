$(document).ready(function () {
    update();

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
        var sex = {"未知": 0, "男": 1, "女": 2};
        $.each(formArray, function (i, item) {
            if (item.name === "sex")
                formObject[item.name] = sex[item.value];
            else
                formObject[item.name] = item.value;

        });
        console.log(formObject);

        alert("222");
        $.ajax({
            url: "/user/info/update/info",
            type: "post",
            data: JSON.stringify(generateInteractionPackage(formObject)),
            contentType: "application/json; charset=utf-8",
            processData: false,
            success: function (data) {
                update();
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

function update() {
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
                        var sex = ["未知", "男", "女"]; //the mapping of number and sex.

                        // store the information to storage
                        sessionStorage.setItem("username", payload.name);
                        sessionStorage.setItem("bio", payload.bio);
                        sessionStorage.setItem("phone", payload.phone);
                        sessionStorage.setItem("email", payload.email);
                        sessionStorage.setItem("sex", sex[payload.sex]);

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
}