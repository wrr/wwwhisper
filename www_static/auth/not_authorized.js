/*!
 * wwwhisper - web access control.
 */
(function () {
  'use strict';

  $('#logout').click(function() {
    var net = new wwwhisper.Net();

    net.ajax('POST', '/wwwhisper/auth/api/logout/', {}, function() {
      window.top.location = '/wwwhisper/auth/goodbye.html';
    });
    return false;
  });

}());
