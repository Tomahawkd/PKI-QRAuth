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
                if (msg.status === 0) {
                    var payload = parseInteractionPackage(data);
                    if (payload) {
                        for (var log in data) {
                            $("tbody").append("<tr>" + "<td>" + log.time + "</td>" +
                                "<td>" + log.IP + "</td>" + "<td>" + log.device + "</td>" +
                                "<td>" + log.message + "</td></tr>");
                        }
                    }
                } else if (msg.status === 1) {
                    $(".error_box").text("注册失败！");
                }
            }
        },

        error: function (data) {
            console.log(data.message);
        }
    })
});