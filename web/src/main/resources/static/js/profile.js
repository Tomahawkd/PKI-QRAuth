$(document).ready(function() {
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
})