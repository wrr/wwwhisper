/*!
 * wwwhisper - web access control.
 */
(function () {
  'use strict';
  var net = new wwwhisper.Net();

  function getById(id) {
    return document.getElementById(id);
  }

  // Make sure a user is authenticated.
  net.ajax('GET', '/wwwhisper/auth/api/whoami/', null,
           function(result) {
             // Logged in.
             getById('email').innerText = result.email;
             getById('authenticated').classList.remove('hide');
             getById('logout').addEventListener('click', function() {
               net.ajax(
                 'POST', '/wwwhisper/auth/api/logout/', {}, function() {
                   window.top.location = '/wwwhisper/auth/goodbye';
                 });
               return false;
             });
           },
           function(errorMessage, errorStatus) {
             if (errorStatus === 401) {
               getById('authenticated').classList.add('hide');
               getById('not-authenticated').classList.remove('hide');
             } else {
               // Other error.
               document.getElementsByTagName('html')[0].innerText =
                 errorMessage;
             }
           });
}());
