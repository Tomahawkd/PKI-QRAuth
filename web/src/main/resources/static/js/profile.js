$(document).ready(function () {
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

        $.ajax({
            url: "/user/info/update/info",
            type: "post",
            data: JSON.stringify(formObject),
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

function update() {

}

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