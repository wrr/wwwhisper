/*!
 * wwwhisper - web access control.
 */
(function () {
  'use strict';
  const net = new wwwhisper.Net();

  function getById(id) {
    return document.getElementById(id);
  }

  function login() {
    const hashParams = new URLSearchParams(window.location.hash.substring(1));

    let next = hashParams.get('next');
    if (!next || !next.startsWith('/') || next.startsWith('//')) {
      next = '/';
    }
    const token = hashParams.get('token');
    net.ajax('POST', '/wwwhisper/auth/api/login/',
             {
               'token' : token
             },
             function() {
               if (BroadcastChannel) {
                 const broadcast = new BroadcastChannel(
                   'wwwhisper-login-success');
                 broadcast.postMessage('');
                 broadcast.close();
               }
               window.location.replace(next);
             },
             function(errorMessage, errorStatus, isTextPlain) {
               if (isTextPlain) {
                 getById('error-message').innerText = errorMessage;
                 getById('error').classList.remove('hide');
               } else {
                 document.getElementsByTagName('html')[0].innerHTML =
                   errorMessage;
               }
             });
  }

  login();

}());
