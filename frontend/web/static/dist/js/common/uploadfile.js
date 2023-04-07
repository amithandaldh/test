(function ($) {
    $.fn.uploadFile = function (options) {
        var defaults = {
            maxFilesize: 1,
            uploadMultiple: false,
            addRemoveLinks : true,
            acceptedFiles : "image/*",
            containerId : '',
            onSuccess: function () {},
            onError: function () {},
            beforeSend: function () {},
            beforeAdded: function () {},
            onComplete: function () {}
        };

        var opts = $.extend({}, defaults, options);
        var $modal = $('#uploadImageModal');
        Dropzone.autoDiscover = false;
        return this.each(function () {
            var elem = $(this);
            $(elem).on('click', function (e) {
                e.preventDefault();
                e.stopPropagation();
                $.fn.upload($modal, opts, $(this)); 
            });
        });
    };
    
    $.fn.upload = function ($modal, opts) {

        var str = opts.containerId.toString();

        str = str.replace( /(<([^>]+)>)/ig, '');
        str = str.replace( '/', '');
        str = str.replace( '\\', '');
        str = str.replace( '"', '');
        str = str.replace( '>', '');
        str = str.replace( '<', '');
        str = str.replace( ' ', '');
        opts.containerId = str.replace( "'", '');

        opts.containerId = $('<textarea/>').text(opts.containerId).html();

        setTimeout(function () {
            $.post(baseHttpPath + '/api/upload-file/upload-modal', {id: opts.containerId}, function (data) {

                $modal.html(data).modal('show');
            });
        }, 500);
         
         
        $('#uploadImageModal').on('shown.bs.modal', function (e) {

            $("#upload-dropzone-file_" + opts.containerId).dropzone({
                maxFiles: opts.maxImage,
                paramName: "file",
                autoDiscover: false,
                addRemoveLinks: opts.addRemoveLinks,
                maxFilesize: opts.maxFilesize,
                uploadMultiple: opts.uploadMultiple,
                acceptedFiles: opts.acceptedFiles,
                url: baseHttpPath + "/api/upload-file/upload",
                init: function () {

                    this.on("addedfile", function (file) {
                        if (opts.beforeAdded && typeof opts.beforeAdded === 'function') {
                            opts.beforeAdded(file);
                        }
                    });
                    this.on("sending", function (file, xhr, formData) {
                        // formData.append('cloudUpload', 1);
                        if (opts.beforeSend && typeof opts.beforeSend === 'function') {
                            opts.beforeSend(file, xhr, formData);
                        }
                    });
                    this.on("success", function (file, response) {
                        if (opts.onSuccess && typeof opts.onSuccess === 'function') {
                            opts.onSuccess(file, response);
                        }
                    });
                    this.on("complete", function (file) {
                        if (opts.onComplete && typeof opts.onComplete === 'function') {
                            opts.onComplete(file);
                        }
                    });
                }
            });

        });
    };
}(jQuery));