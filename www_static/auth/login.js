/*!
 * wwwhisper - web access control.
 */
(function () {
  'use strict';
  var net = new wwwhisper.Net();

  /**
   * Requests a login token to be send to the user provided email
   * address.
   */
  function login(email) {
    $('.entered-email').text(email);
    net.ajax('POST', '/wwwhisper/auth/api/send-token/',
             {
               'email' : email,
               'path': window.location.pathname
             },
             function() {
               $('#intro').addClass('hide');
               $('#login-form').addClass('hide');
               $('#token-send-success').removeClass('hide');
             },
             function(errorMessage, errorStatus) {
               $('#token-send-error-message').text(errorMessage);
               $('#token-send-error').removeClass('hide');
             });
  }

  $('#login-required').removeClass('hide');
  $('#login-form').removeClass('hide');

  $('#login-form').submit(function() {
    var email = $.trim($('#email').val());
    $('#token-send-error').addClass('hide');
    if (email.length !== 0) {
      login(email);
    }
    return false;
  });

}());
