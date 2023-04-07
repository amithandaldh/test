(function ($) {
    
    $.fn.General_ShowNotification = function (options) {
        var defaults = {
            message: '',
            type: 'success',
            timeout: 4000
        };

        var opts = $.extend({}, defaults, options);

        $.notify({
            // options
            //title: 'Bootstrap notify',
            message: opts.message,
        }, {
            // settings
            element: 'body',
            position: null,
            type: opts.type,
            allow_dismiss: true,
            newest_on_top: false,
            showProgressbar: false,
            placement: {
                from: "top",
                align: "right"
            },
            offset: 20,
            spacing: 10,
            z_index: 1031,
            delay: 5000,
            timer: 1000,
            url_target: '_blank',
            mouse_over: null,
            animate: {
                enter: 'animated fadeInDown',
                exit: 'animated fadeOutUp'
            },
            onShow: null,
            onShown: null,
            onClose: null,
            onClosed: null,
            icon_type: 'class'
        });
    };

    //Show Error Message
    $.fn.General_ShowErrorMessage = function (options) {
        var defaults = {
            message: '',
            type: 'error',
            timeout: 2000,
            title: 'Error',
            eventCallback: function () {}
        };

        var opts = $.extend({}, defaults, options);

        bootbox.alert({
            title: opts.title,
            message: opts.message,
            className: "modal__wrapper",
            buttons: {
                ok: {
                    label: 'Ok',
                    className: 'c-button c-button-rounded c-button-inverse'
                }
            },
            callback: function () {
                if (opts.eventCallback && typeof opts.eventCallback === 'function') {
                    opts.eventCallback();
                }
            }
        });
    };
    
    //Show Error Message
    $.fn.ShowFlashMessages = function (options) {
        var defaults = {
            message: '',
            type: 'error',
        };

        var opts = $.extend({}, defaults, options);
        var obj =  $('.page-main-content > .container > .content-wrap');
        if (opts.type === 'error') {
            obj.prepend('<div class="alert alert-danger alert-dismissible fade in" role="alert">\n\
            <button class="close" aria-label="Close" data-dismiss="alert" type="button">\n\
            <span aria-hidden="true">×</span></button><p>' + opts.message + '</p></div>');
        } else {

            obj.prepend('<div class="alert alert-success alert-dismissible fade in" role="alert">\n\
            <button class="close" aria-label="Close" data-dismiss="alert" type="button">\n\
            <span aria-hidden="true">×</span></button><p>' + opts.message + '</p></div>');
        }
    };
    
    $.fn.hideScreenLoader = function (options) {
        var defaults = {};
        var opts = $.extend({}, defaults, options);
        $('#globalLoader').hide();
        $("body").removeClass("loading-loader");
    };
    
    $.fn.showScreenLoader = function (options) {
        var defaults = {};
        var opts = $.extend({}, defaults, options);
        $('#globalLoader').show();
        $("body").addClass("loading-loader");
    };
    
     $('.deleteConfirmation').on('click', function (e) {
        e.preventDefault();
        var elem = $(this);
        var url = elem.data('url');
        if(typeof url === "undefined" || url  === "") {
            return;
        }

        var csrfKey = $('meta[name=csrf-param]').prop('content');
        var csrfVal = $('meta[name=csrf-token]').prop('content');

        url = url + '&' + csrfKey + '=' +csrfVal;
        
        bootbox.confirm({
            title: "Confirm",
            message: 'Do you really want to delete this record?',
            className: "modal__wrapper",
            buttons: {
                confirm: {
                    label: 'Yes',
                    className: 'c-button c-button-rounded c-button-success'
                },
                cancel: {
                    label: 'Cancel',
                    className: 'c-button c-button-rounded c-button-inverse'
                }
            },
            callback: function (result) {
                if (result == true) {
                    window.location = url;
                }

            }
        });
    });
    
    $('body').on('click', '.dismissNotification', function(e){
        e.preventDefault();
        $(this).closest('.c-alerts').remove();
    });
   
}(jQuery));