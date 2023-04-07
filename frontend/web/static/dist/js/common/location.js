var LocationController = (function ($) {
    return {
        getState: function () {
            $('.country').on('change', function (e) {
                e.preventDefault();
                var elem = $(this);
                var countrycode = elem.val();
                if (countrycode === "") {
                    $(".district,.state").val('');
                    $(".district,.state").trigger("chosen:updated");
                    return;
                }

                $.ajax({type: 'post',
                    url: baseHttpPath + '/api/location/get-state',
                    dataType: 'json',
                    data: {countrycode: countrycode, _csrf: yii.getCsrfToken()},
                    success: function (data, textStatus, jqXHR) {
                        if (data.success == "1") {
                            $('.state').html(data.template);
                            $(".state").trigger("chosen:updated");
                        }
                    },
                    error: function (jqXHR, textStatus, errorThrown) {
                        $().ShowFlashMessages({type: 'error', message: jqXHR.responseText});
                    },
                    beforeSend: function (jqXHR, settings) {
                         $().showScreenLoader();
                    },
                    complete: function (jqXHR, textStatus) {
                        $().hideScreenLoader();
                    }
                });
            });
        },
        getDistrict: function () { 
            $('.state').on('change', function (e) {
                 
                e.preventDefault();
                var elem = $(this);
                var stateId = elem.val();
                var districtClass = elem.data('districtclass');
                
                if (stateId === "") {
                    
                    $(".district").val('');
                    $(".district").trigger("chosen:updated");
                    return;
                }

                $.ajax({
                    type: 'post',
                    url: baseHttpPath + '/api/location/get-district',
                    dataType: 'json',
                    data: {statecode: stateId, _csrf: yii.getCsrfToken()},
                    success: function (data, textStatus, jqXHR) {
                        if (data.success == "1") {
                            $(".district").html(data.template);
                            $(".district").trigger("chosen:updated");

                            if (districtClass !== '') {
                                $("." + districtClass).html(data.template);
                                $("." + districtClass).trigger("chosen:updated");
                            }
                        }
                    },
                    error: function (jqXHR, textStatus, errorThrown) {
                        //$.fn.ShowFlashMessages({type: 'error', message: jqXHR.responseText});
                    },
                    beforeSend: function (jqXHR, settings) {
                        //$.fn.showScreenLoader();
                    },
                    complete: function (jqXHR, textStatus) {
                        //$.fn.hideScreenLoader();
                    }
                });
            });
        },
        getBlock: function () { 
            $('.district').on('change', function (e) {
                e.preventDefault();
                var elem = $(this);
                var districtCode = elem.val();
                if (districtCode === "") {
                    $(".block").val('');
                    $(".block").trigger("chosen:updated");
                    return;
                }

                $.ajax({type: 'post',
                    url: baseHttpPath + '/api/location/get-block',
                    dataType: 'json',
                    data: {districtCode: districtCode, _csrf: yii.getCsrfToken()},
                    success: function (data, textStatus, jqXHR) {
                        if (data.success == "1") {
                            $(".block").html(data.template);
                            $(".block").trigger("chosen:updated");
                        }
                    },
                    error: function (jqXHR, textStatus, errorThrown) {
                        $.fn.ShowFlashMessages({type: 'error', message: jqXHR.responseText});
                    },
                    beforeSend: function (jqXHR, settings) {
                        $.fn.showScreenLoader();
                    },
                    complete: function (jqXHR, textStatus) {
                        $.fn.hideScreenLoader();
                    }
                });
            });
        },
        getVillage: function () { 
            $('.block').on('change', function (e) {
                e.preventDefault();
                var elem = $(this);
                var blockCode = elem.val();
                if (blockCode === "") {
                    $(".village").val('');
                    $(".village").trigger("chosen:updated");
                    return;
                }

                $.ajax({type: 'post',
                    url: baseHttpPath + '/api/location/get-village',
                    dataType: 'json',
                    data: {blockCode: blockCode, _csrf: yii.getCsrfToken()},
                    success: function (data, textStatus, jqXHR) {
                        if (data.success == "1") {
                            $(".village").html(data.template);
                            $(".village").trigger("chosen:updated");
                        }
                    },
                    error: function (jqXHR, textStatus, errorThrown) {
                        $.fn.ShowFlashMessages({type: 'error', message: jqXHR.responseText});
                    },
                    beforeSend: function (jqXHR, settings) {
                        $.fn.showScreenLoader();
                    },
                    complete: function (jqXHR, textStatus) {
                        $.fn.hideScreenLoader();
                    }
                });
            });
        },
        fromDatePicker: function () {
            $(".from__date").datepicker({
                format: 'dd-mm-yyyy',
                autoclose: true
            }).on('changeDate', function (selected) {
                var startDate = new Date(selected.date.valueOf());
                $('.to__date').datepicker('setStartDate', startDate);
            }).on('clearDate', function (selected) {
                $('.to__date').datepicker('setStartDate', null);
            });
        },
        toDatePicker: function () {
            $(".to__date").datepicker({
                format: 'dd-mm-yyyy',
                autoclose: true
            }).on('changeDate', function (selected) {
                var endDate = new Date(selected.date.valueOf());
                $('.from__date').datepicker('setEndDate', endDate);
            }).on('clearDate', function (selected) {
                $('.from__date').datepicker('setEndDate', null);
            });
        }
    };
}(jQuery));