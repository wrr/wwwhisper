/*!
 * wwwhisper - web access control.
 */
(function () {
  'use strict';

  function logout() {
    var net = new wwwhisper.Net();
    net.ajax('POST', '/wwwhisper/auth/api/logout/', {}, function() {
      window.top.location = '/wwwhisper/auth/goodbye.html';
    });
    return false;
  }

  document.getElementById('logout').addEventListener('click', logout);
}());
