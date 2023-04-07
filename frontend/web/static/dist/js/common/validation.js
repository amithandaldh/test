(function ($) {

    $.fn.focusOutFunction();

    $.fn.inputTextBox = function (options) {
       
        var defaults = {
            id: null,
            class: '.js-textboxRequired',
            container: ".field",
            input: "#customer-name",
            errorCls: ".help-block-error",
            required: function (options1) {
                var defaults1 = {
                    success: function () {
                        
                    },
                    error: function () {
                    },
                };
                $.extend({}, defaults1, options1);
            }

        };


        var opts = $.extend({}, defaults, options);

        if (typeof opts.required === "object") {
            return $.fn.required(opts);
        }


    };

    $.fn.required = function (options) {
        $(options.class).on('focusout', function (e) {
            var id = $(this).attr('id');
            var label = $(this).attr('data-label');
            if ($(this).val() == '') {
                $(options.container + '-' + id).addClass('has-error').removeClass('has-success');
                $(options.container + '-' + id).find('.help-block').addClass('help-block-error');
                $(options.container + '-' + id).find('.help-block').html(label);

                if (typeof options.required.error === "function") {
                    return options.required.error(options, $(this));
                }
            } else {
                $(options.container + '-' + id).removeClass('has-error').addClass('has-success');
                $(options.container + '-' + id).find('.help-block').removeClass('help-block-error');
                $(options.container + '-' + id).find('.help-block').html('');
                if (typeof options.required.success === "function") {
                    return options.required.success(options, $(this));
                }
            }
        });

    }

    $.fn.pincode = function (options) {
        
        var defaults = {
            id: null,
            class: '.js-textboxPincode',
            container: ".field",
            input: "#customer-name",
            error: ".help-block-error",
        };
         
        var opts = $.extend({}, defaults, options);

        $(opts.class).on('focusout', function (e) {

            var id = $(this).attr('id');
            var label = $(this).attr('data-label');

            if (!$.fn.textboxPincode($(this))) {
                
                $(opts.container + '-' + id).addClass('has-error').removeClass('has-success');
                $(opts.container + '-' + id).find('.help-block').addClass('help-block-error');
                $(opts.container + '-' + id).find('.help-block').html('Not a valid pincode');
            } else {
                
                $(opts.container + '-' + id).removeClass('has-error').addClass('has-success');
                $(opts.container + '-' + id).find('.help-block').removeClass('help-block-error');
                $(opts.container + '-' + id).find('.help-block').html('');
            }
        });

    }
    $.fn.number = function (options) {

        var defaults = {
            id: null,
            class: '.js-textboxNumber',
            container: ".field",
            input: "#customer-name",
            error: ".help-block-error",
        };

        var opts = $.extend({}, defaults, options);

        $(opts.class).on('focusout', function (e) {

            var id = $(this).attr('id');
            var label = $(this).attr('data-label');

            if ($(this).val() == '') {
                $(opts.container + '-' + id).addClass('has-error').removeClass('has-success');
                $(opts.container + '-' + id).find('.help-block').addClass('help-block-error');
                $(opts.container + '-' + id).find('.help-block').html(label);
            } else {
                $(opts.container + '-' + id).removeClass('has-error').addClass('has-success');
                $(opts.container + '-' + id).find('.help-block').removeClass('help-block-error');
                $(opts.container + '-' + id).find('.help-block').html('');
            }
        });

    }

    $.fn.email = function (options) {

        var defaults = {
            id: null,
            class: '.js-textboxEmail',
            container: ".field",
            input: "#customer-name",
            error: ".help-block-error",
        };

        var opts = $.extend({}, defaults, options);

        $(opts.class).on('focusout', function (e) {

            var id = $(this).attr('id');
            var label = $(this).attr('data-label');

            if ($(this).val() == '') {
                $(opts.container + '-' + id).addClass('has-error').removeClass('has-success');
                $(opts.container + '-' + id).find('.help-block').addClass('help-block-error');
                $(opts.container + '-' + id).find('.help-block').html(label);
            } else {
                $(opts.container + '-' + id).removeClass('has-error').addClass('has-success');
                $(opts.container + '-' + id).find('.help-block').removeClass('help-block-error');
                $(opts.container + '-' + id).find('.help-block').html('');
            }
        });

    }
    $.fn.mobile = function (options) {

        var defaults = {
            id: null,
            class: '.js-textboxMobile',
            container: ".field",
            input: "#customer-name",
            error: ".help-block-error",
        };

        var opts = $.extend({}, defaults, options);

        $(opts.class).on('focusout', function (e) {

            var id = $(this).attr('id');
            var label = $(this).attr('data-label');

            if ($(this).val() == '') {
                $(opts.container + '-' + id).addClass('has-error').removeClass('has-success');
                $(opts.container + '-' + id).find('.help-block').addClass('help-block-error');
                $(opts.container + '-' + id).find('.help-block').html(label);
            } else {
                $(opts.container + '-' + id).removeClass('has-error').addClass('has-success');
                $(opts.container + '-' + id).find('.help-block').removeClass('help-block-error');
                $(opts.container + '-' + id).find('.help-block').html('');
            }
        });

    }

    $.fn.name = function (options) {

        var defaults = {
            id: null,
            class: '.js-textboxName',
            container: ".field",
            input: "#customer-name",
            error: ".help-block-error",
        };

        var opts = $.extend({}, defaults, options);

        $(opts.class).on('focusout', function (e) {

            var id = $(this).attr('id');
            var label = $(this).attr('data-label');

            if ($(this).val() == '') {
                $(opts.container + '-' + id).addClass('has-error').removeClass('has-success');
                $(opts.container + '-' + id).find('.help-block').addClass('help-block-error');
                $(opts.container + '-' + id).find('.help-block').html(label);
            } else {
                $(opts.container + '-' + id).removeClass('has-error').addClass('has-success');
                $(opts.container + '-' + id).find('.help-block').removeClass('help-block-error');
                $(opts.container + '-' + id).find('.help-block').html('');
            }
        });

    }
     
    $.fn.aadharcard = function (options) {

        var defaults = {
            id: null,
            class: '.js-textboxAdharCard',
            container: ".field",
            input: "#customer-name",
            error: ".help-block-error",
        };

        var opts = $.extend({}, defaults, options);

        $(opts.class).on('focusout', function (e) {

            var id = $(this).attr('id');
            var label = $(this).attr('data-label');

            if ($(this).val() == '') {
                $(opts.container + '-' + id).addClass('has-error').removeClass('has-success');
                $(opts.container + '-' + id).find('.help-block').addClass('help-block-error');
                $(opts.container + '-' + id).find('.help-block').html(label);
            } else {
                $(opts.container + '-' + id).removeClass('has-error').addClass('has-success');
                $(opts.container + '-' + id).find('.help-block').removeClass('help-block-error');
                $(opts.container + '-' + id).find('.help-block').html('');
            }
        });

    }
    $.fn.pancard = function (options) {

        var defaults = {
            id: null,
            class: '.js-textboxPancard',
            container: ".field",
            input: "#customer-name",
            error: ".help-block-error",
        };

        var opts = $.extend({}, defaults, options);

        $(opts.class).on('focusout', function (e) {

            var id = $(this).attr('id');
            var label = $(this).attr('data-label');

            if ($(this).val() == '') {
                $(opts.container + '-' + id).addClass('has-error').removeClass('has-success');
                $(opts.container + '-' + id).find('.help-block').addClass('help-block-error');
                $(opts.container + '-' + id).find('.help-block').html(label);
            } else {
                $(opts.container + '-' + id).removeClass('has-error').addClass('has-success');
                $(opts.container + '-' + id).find('.help-block').removeClass('help-block-error');
                $(opts.container + '-' + id).find('.help-block').html('');
            }
        });

    }
    $.fn.password = function (options) {

        var defaults = {
            id: null,
            class: '.js-textboxPassword',
            container: ".field",
            input: "#customer-name",
            error: ".help-block-error",
        };

        var opts = $.extend({}, defaults, options);

        $(opts.class).on('focusout', function (e) {

            var id = $(this).attr('id');
            var label = $(this).attr('data-label');

            if ($(this).val() == '') {
                $(opts.container + '-' + id).addClass('has-error').removeClass('has-success');
                $(opts.container + '-' + id).find('.help-block').addClass('help-block-error');
                $(opts.container + '-' + id).find('.help-block').html(label);
            } else {
                $(opts.container + '-' + id).removeClass('has-error').addClass('has-success');
                $(opts.container + '-' + id).find('.help-block').removeClass('help-block-error');
                $(opts.container + '-' + id).find('.help-block').html('');
            }
        });

    }


}(jQuery));