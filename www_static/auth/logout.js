/*!
 * wwwhisper - web access control.
 */
(function () {
  'use strict';
  var net = new wwwhisper.Net();

  // Make sure a user is authenticated.
  net.ajax('GET', '/wwwhisper/auth/api/whoami/', null,
           function(result) {
             // Logged in.
             $('#email').text(result.email);
             $('#authenticated').removeClass('hide');
             $('#logout').click(function() {
               net.ajax(
                 'POST', '/wwwhisper/auth/api/logout/', {}, function() {
                   window.top.location = '/wwwhisper/auth/goodbye.html';
                 });
               return false;
             });
           },
           function(errorMessage, errorStatus) {
             if (errorStatus === 401) {
               $('#authenticated').addClass('hide');
               $('#not-authenticated').removeClass('hide');
             } else {
               // Other error.
               $('body').html(errorMessage);
             }
           });
}());
