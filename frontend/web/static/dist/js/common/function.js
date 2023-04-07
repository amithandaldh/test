(function ($) {

    $.fn.validation = function (options) {

        var defaults = {
            formCls: '.js-form',
            submitCls: '.js-submitForm',
            nextErrorCls: '.help-block',
        };
        this.options = $.extend(defaults, options);

        var $formCls = this.options.formCls;
        var $submitCls = this.options.submitCls;
        var nextErrorCls = this.options.nextErrorCls;
        var isValid = false;

        var message = {
             notvalid : 'is invalid', 
            'number': 'Not a valid No',
            'email': 'is not valid.',
            'mobileNumber': 'is not valid',
            'negaitveNumber': 'Not a valid negative number',
            'positiveNumber': 'Not a valid positive number',
            'folderName': 'Not a valid folder name',
            'name': 'Not a valid name',
            'required': 'cannot be blank.',
            'adhar': 'Not a valid aadhar',
            'pancard': 'Not a valid pancard',
            'pincode': 'Not a valid pincode',
            'password': 'Not a valid password',
        };

        $.fn.focusOutFunction($formCls, nextErrorCls, message);
//        $($formCls).on('click', $submitCls, function (e) {
//            e.preventDefault();
//            // need to check the 
//            var k = isValid($formCls);
//            if (k) {
//                console.log('submit success');
//                // $($formCls).submit();
//            } else {
//                console.log('not subit');
//                return;
//            }
//
//        });

        var isValid = function (formCls) {
            var returnValue = true; //{'valid':true, 'message':''};

            $(formCls + ' input.js-textboxNumber').each(function () {
                if (!$.fn.textboxNumber($(this))) {
                    returnValue = false; // {'valid':false, 'message':message.number};
                    $(this).next(nextErrorCls).text(message.number);

                }
            });

            $(formCls + ' input.js-textboxEmail').each(function () {
                if (!$.fn.textboxEmail($(this))) {
                    $(this).next(nextErrorCls).text(message.email);
                    returnValue = false; //{'valid':false, 'message':message.email};
                }
            });

            $(formCls + ' input.js-textboxMobile').each(function () {
                if (!$.fn.textboxMobile($(this))) {
                    $(this).next(nextErrorCls).text(message.mobileNumber);
                    returnValue = false;// {'valid':false, 'message':message.mobileNumber};
                }
            });

            $(formCls + ' input.js-textboxNegativeNumber').each(function () {
                if (!$.fn.textboxNegativeNumber($(this))) {
                    returnValue = false; //{'valid':false, 'message':message.required};
                    $(this).next(nextErrorCls).text(message.negaitveNumber);
                }
            });

            $(formCls + ' input.js-textboxPositiveNumber').each(function () {
                if (!$.fn.textboxPositiveNumber($(this))) {
                    returnValue = false; //{'valid':false, 'message':message.required};
                    $(this).next(nextErrorCls).text(message.positiveNumber);
                }
            });

            $(formCls + ' input.js-textboxFolderName').each(function () {
                if (!$.fn.textboxFolderName($(this))) {
                    returnValue = false; //{'valid':false, 'message':message.required};
                    $(this).next(nextErrorCls).text(message.folderName);
                }
            });

            $(formCls + ' input.js-textboxName').each(function () {
                if (!$.fn.textboxName($(this))) {
                    returnValue = false; //{'valid':false, 'message':message.required};
                    $(this).next(nextErrorCls).text(message.name);
                }
            });

            $(formCls + ' input.js-textboxRequired').each(function () {
                if (!$.fn.textboxRequired($(this))) {
                    $(this).next(nextErrorCls).text(message.required);
                    returnValue = false; //{'valid':false, 'message':message.required};
                }
            });

            $(formCls + ' input.js-textboxAdharCard').each(function () {
                if (!$.fn.textboxAdharCard($(this))) {
                    returnValue = false; //{'valid':false, 'message':message.required};
                    $(this).next(nextErrorCls).text(message.adhar);
                }
            });

            $(formCls + ' input.js-textboxPancard').each(function () {
                if (!$.fn.textboxPancard($(this))) {
                    returnValue = false; //{'valid':false, 'message':message.required};
                    $(this).next(nextErrorCls).text(message.pancard);

                }
            });

            $(formCls + ' input.js-textboxPincode').each(function () {
                if (!$.fn.textboxPincode($(this))) {
                    returnValue = false; //{'valid':false, 'message':message.required};
                    $(this).next(nextErrorCls).text(message.pincode);
                }
            });

            $(formCls + ' input.js-textboxPassword').each(function () {
                if (!$.fn.textboxPassword($(this))) {
                    returnValue = false; //{'valid':false, 'message':message.required};
                    $(this).next(nextErrorCls).text(message.password);
                }
            });

            return returnValue;

        }

    }

    $.fn.focusOutFunction = function ($formCls, nextErrorCls, message) {

        var showMessage = false;
        $($formCls + ' input.js-textboxNumber').on('focusout', function (e) {

            var id = $(this).attr('id');

            if (!$.fn.textboxNumber($(this))) {

                showMessage = true;
                $('.field-' + id).addClass('has-error').removeClass('has-success');
                $('.field-' + id).find('.help-block').addClass('help-block-error');
                $('.field-' + id).find('.help-block').html(message.number);

            } else {
                showMessage = false;

                $('.field-' + id).removeClass('has-error').addClass('has-success');
                $('.field-' + id).find('.help-block').removeClass('help-block-error');
                $('.field-' + id).find('.help-block').html('');
            }
        });

        $($formCls + ' input.js-textboxEmail').on('focusout', function (e) {

            var id = $(this).attr('id');
            var label = $(this).attr('data-label');
            if (!$.fn.textboxEmail($(this))) {
               
                showMessage = true;
                $('.field-' + id).addClass('has-error').removeClass('has-success');
                $('.field-' + id).find('.help-block').addClass('help-block-error');
                $('.field-' + id).find('.help-block').html(label + ' ' + message.notvalid);

            } else {
                
                $('.field-' + id).removeClass('has-error').addClass('has-success');
                $('.field-' + id).find('.help-block').removeClass('help-block-error');
                $('.field-' + id).find('.help-block').html('');
            }
        });

        $($formCls + ' input.js-textboxMobile').on('focusout', function (e) {
            var id = $(this).attr('id');
            var label = $(this).attr('data-label');
            if (!$.fn.textboxMobile($(this))) {
                showMessage = true;
                $('.field-' + id).addClass('has-error').removeClass('has-success');
                $('.field-' + id).find('.help-block').addClass('help-block-error');
                $('.field-' + id).find('.help-block').html(label + ' ' + message.notvalid);
            } else {
                $('.field-' + id).removeClass('has-error').addClass('has-success');
                $('.field-' + id).find('.help-block').removeClass('help-block-error');
                $('.field-' + id).find('.help-block').html('');
            }
        });

        $($formCls + ' input.js-textboxName').on('focusout', function (e) {
            var id = $(this).attr('id');
            var label = $(this).attr('data-label');
            if (!$.fn.textboxName($(this))) {
                showMessage = true;
                $('.field-' + id).addClass('has-error').removeClass('has-success');
                $('.field-' + id).find('.help-block').addClass('help-block-error');
                $('.field-' + id).find('.help-block').html(label + ' ' + message.notvalid);
            } else {
                $('.field-' + id).removeClass('has-error').addClass('has-success');
                $('.field-' + id).find('.help-block').removeClass('help-block-error');
                $('.field-' + id).find('.help-block').html('');
            }
        });

        $($formCls + ' input.js-textboxRequired').on('focusout', function (e) {
            var id = $(this).attr('id');
            var label = $(this).attr('data-label');

            if (!$.fn.textboxRequired($(this))) {

                showMessage = true;
                $('.field-' + id).addClass('has-error').removeClass('has-success');
                $('.field-' + id).find('.help-block').addClass('help-block-error');
                $('.field-' + id).find('.help-block').html(label + ' ' + message.required);
                

            } else {

                $('.field-' + id).removeClass('has-error').addClass('has-success');
                $('.field-' + id).find('.help-block').removeClass('help-block-error');
                $('.field-' + id).find('.help-block').html('');


            }
        });
        
        $($formCls + ' input.js-textboxPincode').on('focusout', function (e) {
            var id = $(this).attr('id');
            if (!$.fn.textboxPincode($(this))) {
                showMessage = true;
                $('.field-' + id).addClass('has-error').removeClass('has-success');
                $('.field-' + id).find('.help-block').addClass('help-block-error');
                $('.field-' + id).find('.help-block').html(message.pincode);

            } else {
                $('.field-' + id).removeClass('has-error').addClass('has-success');
                $('.field-' + id).find('.help-block').removeClass('help-block-error');
                $('.field-' + id).find('.help-block').html('');
            }
        });
        
        $($formCls + ' input.js-textboxNegativeNumber').on('focusout', function (e) {
            var id = $(this).attr('id');
            if (!$.fn.textboxNegativeNumber($(this))) {

                showMessage = true;
                $('.field-' + id).addClass('has-error').removeClass('has-success');
                $('.field-' + id).find('.help-block').addClass('help-block-error');
                $('.field-' + id).find('.help-block').html(message.negaitveNumber);
            } else {
                $('.field-' + id).removeClass('has-error').addClass('has-success');
                $('.field-' + id).find('.help-block').removeClass('help-block-error');
                $('.field-' + id).find('.help-block').html('');
            }
        });

        $($formCls + ' input.js-textboxPositiveNumber').on('focusout', function (e) {
            var id = $(this).attr('id');
            if (!$.fn.textboxPositiveNumber($(this))) {
                showMessage = true;
                $('.field-' + id).addClass('has-error').removeClass('has-success');
                $('.field-' + id).find('.help-block').addClass('help-block-error');
                $('.field-' + id).find('.help-block').html(message.positiveNumber);
            } else {
                $('.field-' + id).removeClass('has-error').addClass('has-success');
                $('.field-' + id).find('.help-block').removeClass('help-block-error');
                $('.field-' + id).find('.help-block').html('');
            }
        });

        $($formCls + ' input.js-textboxFolderName').on('focusout', function (e) {
            var id = $(this).attr('id');
            if (!$.fn.textboxFolderName($(this))) {
                showMessage = true;
                $('.field-' + id).addClass('has-error').removeClass('has-success');
                $('.field-' + id).find('.help-block').addClass('help-block-error');
                $('.field-' + id).find('.help-block').html(message.folderName);
            } else {
                $('.field-' + id).removeClass('has-error').addClass('has-success');
                $('.field-' + id).find('.help-block').removeClass('help-block-error');
                $('.field-' + id).find('.help-block').html('');
            }
        });


        $($formCls + ' input.js-textboxAdharCard').on('focusout', function (e) {
            var id = $(this).attr('id');
            if (!$.fn.textboxAdharCard($(this))) {

                showMessage = true;
                $('.field-' + id).addClass('has-error').removeClass('has-success');
                $('.field-' + id).find('.help-block').addClass('help-block-error');
                $('.field-' + id).find('.help-block').html(message.adhar);
            } else {
                $('.field-' + id).removeClass('has-error').addClass('has-success');
                $('.field-' + id).find('.help-block').removeClass('help-block-error');
                $('.field-' + id).find('.help-block').html('');
            }
        });

        $($formCls + ' input.js-textboxPancard').on('focusout', function (e) {
            var id = $(this).attr('id');
            if (!$.fn.textboxPancard($(this))) {
                showMessage = true;
                $('.field-' + id).addClass('has-error').removeClass('has-success');
                $('.field-' + id).find('.help-block').addClass('help-block-error');
                $('.field-' + id).find('.help-block').html(message.pancard);
            } else {
                $('.field-' + id).removeClass('has-error').addClass('has-success');
                $('.field-' + id).find('.help-block').removeClass('help-block-error');
                $('.field-' + id).find('.help-block').html('');
            }

        });

        

        $($formCls + ' input.js-textboxPassword').on('focusout', function (e) {
            var id = $(this).attr('id');
            if (!$.fn.textboxPassword($(this))) {
                showMessage = true;
                $('.field-' + id).addClass('has-error').removeClass('has-success');
                $('.field-' + id).find('.help-block').addClass('help-block-error');
                $('.field-' + id).find('.help-block').html(message.password);
            } else {
                $('.field-' + id).removeClass('has-error').addClass('has-success');
                $('.field-' + id).find('.help-block').removeClass('help-block-error');
                $('.field-' + id).find('.help-block').html('');
            }
        });

    }

    $.fn.textboxNumber = function (obj) {
        var value = parseInt($(obj).val());
        if (!$.isNumeric(value) || value === '') {
            return false;
        } else {
            return true;
        }
    }

    $.fn.textboxEmail = function (obj) {
        var email = $(obj).val();
        var pattern = /^\w+@[a-zA-Z_]+?\.[a-zA-Z]{2,3}$/;
        if (pattern.test(email)) {
            return true;
        }
        return false;
    }

    $.fn.textboxMobile = function (obj) {
        var value = $(obj).val().trim().toLowerCase();
        var pattern = /^(\+91[\-\s]?)?[0]?(91)?[789]\d{9}$/;

        if (!pattern.test(value) || value === '') {
            return false;
        } else {
            return true;

        }
    }

    $.fn.textboxPositiveNumber = function (obj) {
        var value = $(obj).val().trim().toLowerCase();

        if (!$.isNumeric(value)) {
            return false;
        }

        if (parseInt(value) >= 0 || value === '') {
            return true;
        }
        return false;
    }

    $.fn.textboxNegativeNumber = function (obj) {
        var value = $(obj).val().trim().toLowerCase();

        if (!$.isNumeric(value)) {
            return false;
        }

        if (parseInt(value) < 0 || value === '') {
            return true;
        }
        return false;
    }

    $.fn.textboxFolderName = function (obj) {
        var folderName = $(obj).val();
        var pattern = /^[a-zA-Z0-9_\- ]+$/;

        if (pattern.test(folderName) || folderName === '') {
            return true;
        }
        return false;
    }

    $.fn.textboxName = function (obj) {

        var name = $(obj).val();
        var pattern = /^[A-Za-z]{3,}[\.]{0,1}[A-Za-z]{0,2}$/;
        if (pattern.test(name) || name === '') {
            return true;
        }
        return false;

    }

    $.fn.textboxRequired = function (obj) {
        var value = $(obj).val().trim().toLowerCase();
        if (value === '') {
            return false;
        } else {
            return true;
        }
    }

    $.fn.textboxAdharCard = function (obj) {
        var uid = $(obj).val();
        var Verhoeff = {
            "d": [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
                [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
                [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
                [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
                [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
                [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
                [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
                [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
                [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
                [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]],
            "p": [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
                [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
                [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
                [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
                [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
                [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
                [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
                [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]],
            "j": [0, 4, 3, 2, 1, 5, 6, 7, 8, 9],
            "check": function (str) {
                var c = 0;
                str.replace(/\D+/g, "").split("").reverse().join("").replace(/[\d]/g, function (u, i) {
                    c = Verhoeff.d[c][Verhoeff.p[i % 8][parseInt(u, 10)]];
                });
                return c;

            },
            "get": function (str) {

                var c = 0;
                str.replace(/\D+/g, "").split("").reverse().join("").replace(/[\d]/g, function (u, i) {
                    c = Verhoeff.d[c][Verhoeff.p[(i + 1) % 8][parseInt(u, 10)]];
                });
                return Verhoeff.j[c];
            }
        };

        String.prototype.verhoeffCheck = (function () {
            var d = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
                [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
                [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
                [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
                [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
                [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
                [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
                [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
                [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
                [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]];
            var p = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
                [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
                [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
                [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
                [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
                [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
                [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
                [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]];

            return function () {
                var c = 0;
                this.replace(/\D+/g, "").split("").reverse().join("").replace(/[\d]/g, function (u, i) {
                    c = d[c][p[i % 8][parseInt(u, 10)]];
                });
                return (c === 0);
            };
        })();

        if (Verhoeff['check'](uid) === 0) {
            return true
        } else {
            return false;
        }
    };

    $.fn.textboxPancard = function (obj) {
        var pancard = $(obj).val();

        var pattern = /([A-Z]){5}([0-9]){4}([A-Z]){1}$/;
        if (pattern.test(pancard) || pancard === '') {
            return true;
        }
        return false;
    }

    $.fn.textboxPincode = function (obj) {
        var pincode = $(obj).val();

        var pattern = /^[1-9][0-9]{5}$/;

        if (pattern.test(pincode) && pincode !== '') {
            return true;
        }
        return false;
    }

    $.fn.textboxPassword = function (obj) {
        var password = $(obj).val();
        var pattern = /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&\*])(?=.{8,})/;
        if (pattern.test(password)) {
            return true;
        }
        return false;
    }

}(jQuery));