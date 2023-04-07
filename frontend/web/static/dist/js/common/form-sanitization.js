
/***********************************/
/* Initalise WOW Js */
/**********************************/

$(document).ready(function () {

});

//Chosen Functions
/*$('.chosen-select').chosen();
$('.chosen-select.js-withoutsearch').chosen({
    "disable_search": true
});*/

$.fn.formSanitization = function () {
    $(".only-number").on("keypress", function (e) {

        var charCode = (e.which) ? e.which : e.keyCode;
        if (charCode != 46 && charCode > 31 && (charCode < 48 || charCode > 57))
            return false;
        else
            return true;
    });

    $(".only-alphabet").on("keypress", function (e) {

        var code = (e.which) ? e.which : event.keyCode;
        if (code == 32 || code == 8 || (code >= 97 && code <= 122) || (code >= 65 && code <= 90))
            return true;
        else
            return false;
    });

    $(".only-integer").on("keypress", function (e) {

        var charCode = (e.which) ? e.which : e.keyCode;
        if (charCode < 48 || charCode > 57)
            return false;
        else
            return true;
    });

    $(".alpha-numeric-with-special").on("keypress", function (e) {

        var code = (e.which) ? e.which : event.keyCode;
        var arr = [32, 39, 33, 8, 44, 45, 46, 47, 58, 59, 63, 64];
        if (jQuery.inArray(code, arr) !== -1 || (code >= 97 && code <= 122) || (code >= 65 && code <= 90) || (code >= 48 && code <= 57))
            return true;
        else
            return false;
    });

    $('.disable-copy-paste').on("cut copy paste", function (e) {
        $.fn.General_ShowNotification({message: 'Not allowed', type: 'warning'});
        e.preventDefault();
    });

};

$(".only-number").on("keypress", function (e) {

    var charCode = (e.which) ? e.which : e.keyCode;
    if (charCode != 46 && charCode > 31 && (charCode < 48 || charCode > 57))
        return false;
    else
        return true;
});

$(".only-integer").on("keypress", function (e) {

    var charCode = (e.which) ? e.which : e.keyCode;
    if (charCode < 48 || charCode > 57)
        return false;
    else
        return true;
});

$(".only-alphabet").on("keypress", function (e) {

    var code = (e.which) ? e.which : event.keyCode;
    if (code == 32 || code == 8 || (code >= 97 && code <= 122) || (code >= 65 && code <= 90))
        return true;
    else
        return false;
});

$(".alpha-numeric-with-special").on("keypress", function (e) {

    var code = (e.which) ? e.which : event.keyCode;
    var arr = [32,39,33,8,44,45,46,47,58,59,63,64];
    if (jQuery.inArray( code, arr ) !== -1 || (code >= 97 && code <= 122) || (code >= 65 && code <= 90) || (code >= 48 && code <= 57))
        return true;
    else
        return false;
});

$('.text-to-upper').keyup(function(){
    $(this).val($(this).val().toUpperCase());
});

$('.disable-copy-paste').on("cut copy paste", function (e) {
    $.fn.General_ShowNotification({message: 'Not allowed', type: 'warning'});
    e.preventDefault();
});

$(".nothing-press").on("keypress", function (e) {
    return false;
});

$(".alpha-numeric").on("keypress", function (e) {

    var code = (e.which) ? e.which : event.keyCode;
    if ((code >= 97 && code <= 122) || (code >= 65 && code <= 90) || (code >= 48 && code <= 57))
        return true;
    else
        return false;
});