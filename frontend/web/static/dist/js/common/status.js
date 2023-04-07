(function ($) {
    $.fn.updateStatus = function (options) {
        var defaults = {
            onSuccess: function () {},
            onError: function () {},
            beforeSend: function () {},
            onComplete: function () {}
        };
        var opts = $.extend({}, defaults, options);
        return this.each(function () {
            var obj = $(this);
            $(obj).on('click', function (e) {
                e.preventDefault();
                e.stopPropagation();
                var elem = $(this);
                var url = elem.data('url');
                if (typeof url === 'undefined' || url === '') {
                    return;
                }

                $.ajax({
                    type: 'GET',
                    url: url,
                    dataType: 'json',
                    success: function (data, textStatus, jqXHR) {
                        if (data.success == "1") {
                            if (data.status == "1") {
                                elem.attr('title', 'Yes');
                                elem.html("<a href='javascript:;'>Yes</a>");
                            } else {
                                elem.attr('title', 'No');
                                elem.html("<a href='javascript:;'>No</a>");
                            }
                        }
                    },
                    error: function (jqXHR, textStatus, errorThrown) {
                        elem.find('.badge').removeClass('badge--spins');
                        alert(jqXHR.responseText);
                    },
                    beforeSend: function (jqXHR, settings) {
                        elem.find('.badge').addClass('badge--spins');
                    },
                    complete: function (jqXHR, textStatus) {
                        elem.find('.badge').removeClass('badge--spins');
                    }
                });
            });
        });
    };
}(jQuery));

var StatusController = (function ($) {
    return {
        update: function () {
            StatusController.Update.init();
        }
    };
}(jQuery));

StatusController.Update = (function ($) {
    var attachEvents = function () {
        $('.updateStatusGrid').updateStatus();
    };
    return {
        init: function () {
            attachEvents();
        }
    };
}(jQuery));