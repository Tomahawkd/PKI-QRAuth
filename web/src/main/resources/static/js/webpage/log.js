$(document).ready(function () {
    $.ajax({
        url: "/user/management/log",
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
                        $("tbody").append("<tr>" + "<td>" + list[index].time + "</td>" +
                            "<td>" + list[index].ip + "</td>" + "<td>" + list[index].device + "</td>" +
                            "<td>" + list[index].message + "</td></tr>");
                    }
                } else {
                    logout();
                }
            }
        },

        error: function (data) {
            $(".error_box").text(data.message);
        }
    })
});