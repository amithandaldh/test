var cropImageModal = $('#cropImageModal');
var cropperObjLocal;
var CropController = (function ($) {
    return {
        crop: function () {
            CropController.CropImage.init();
        },
        cropModalXhr: function (mediaId) {
            setTimeout(function () {
                $.get(baseHttpPath + '/api/upload-file/crop-media-modal', {mediaId: mediaId,  _csrf: yii.getCsrfToken()}, function (data) {
                    $('#cropImageModal').html(data).modal('show');
                    var image = document.querySelector('#cropImageBlock');
                    cropperObjLocal = new Cropper(image, {
                        movable: false,
                        zoomable: false,
                        scalable: false
                    });
                });
            }, 500);
        }
    };
}(jQuery));


CropController.CropImage = (function ($) {
    var attachEvents = function () {
        $('body').on('click', '.croppingImages', function (e) {
            e.preventDefault();
            e.stopPropagation();
            var elem = $(this);

            var mediaId = elem.data('id');
            if (typeof mediaId === "undefined" || mediaId === "") {
                return;
            }

            CropController.cropModalXhr(mediaId);
        });

        cropImageModal.on('hidden.bs.modal', function () {
            cropperObjLocal.destroy();
        });


        // cropImageModal.off('click', '.rotateImage');
        $('body').on('click', '.rotateImage', function (e) {
            cropperObjLocal.rotate(90);
        });

        $('body').on('click', '.rotateReset', function (e) {
            cropperObjLocal.reset();
        });

        var btnClicked = false;
        $('body').off('click', 'button.btnSubmitCrop').on('click', 'button.btnSubmitCrop', function (e) {
            e.preventDefault();
            e.stopPropagation();

            if (btnClicked) {
                return;
            }

            btnClicked = true;
            var btnObj = $(this);

            var mediaId = $('#inputCropMediaId').val();
            if (typeof mediaId === "undefined" || mediaId === "") {
                return;
            }

            var data = cropperObjLocal.getData();
            data.mediaId = mediaId;
            data._csrf = yii.getCsrfToken();

            $.ajax({
                url: baseHttpPath + '/api/upload-file/crop-media',
                type: 'post',
                data: data,
                dataType: 'json',
                success: function (data) {
                    btnClicked = false;
                    if (data.success == "1") {
                        // window.location = window.location;
                    }
                    $('#cropImageModal').modal('hide');
                },
                error: function (jqXHR, textStatus, errorThrown) {
                    $.fn.ShowFlashMessages({type: 'error', message: jqXHR.responseText});
                },
                beforeSend: function (jqXHR, settings) {
                    $(btnObj).html('<i class="fa fa-spin fa-spinner"></i> Please wait...');
                },
                complete: function (jqXHR, textStatus) {
                    $(btnObj).html('<i class="fa fa-save"></i> Save');
                    btnClicked = false;
                }
            });
        });


    };
    return {
        init: function () {
            attachEvents();
        }
    };
}(jQuery));

