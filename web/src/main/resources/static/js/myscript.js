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

    //选择图片，马上预览
     function xmTanUploadImg(obj) {
      var file = obj.files[0];
      console.log(obj);console.log(file);
      console.log("file.size = " + file.size);
      var reader = new FileReader();
      reader.onload = function (e) {
          console.log("成功读取....");
      var img = document.getElementById("avarimgs");
          img.src = e.target.result;
       //或者 img.src = this.result;  //e.target == this
      }
          reader.readAsDataURL(file)
      }
});
