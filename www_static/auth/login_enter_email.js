/*!
 * wwwhisper - web access control.
 */
(function () {
  'use strict';
  var net = new wwwhisper.Net();

  function getById(id) {
    return document.getElementById(id);
  }

  /**
   * Requests a login token to be send to the user provided email
   * address.
   */
  function login(email) {
    var elements = document.getElementsByClassName('entered-email'), i;
    for (i = 0; i < elements.length; ++i) {
      elements[i].innerText = email;
    }
    net.ajax('POST', '/wwwhisper/auth/api/send-token/',
             {
               'email' : email,
               'path': window.location.pathname
             },
             function() {
               getById('intro').classList.add('hide');
               getById('login-form').classList.add('hide');
               getById('token-send-success').classList.remove('hide');
             },
             function(errorMessage, errorStatus, isTextPlain) {
               if (!isTextPlain) {
                 errorMessage = 'server communication error, try again.';
               }
               getById('token-send-error-message').innerText = errorMessage;
               getById('token-send-error').classList.remove('hide');
             });
  }

  getById('login-required').classList.remove('hide');

  var loginForm = getById('login-form');
  loginForm.addEventListener('submit', function(event) {
    var emailInput = getById('email-input');
    var email = emailInput.value.trim();
    event.preventDefault();
    getById('token-send-error').classList.add('hide');
    if (email.length !== 0) {
      login(email);
    } else {
      emailInput.focus();
    }
    return false;
  });

  if (BroadcastChannel) {
    var broadcast = new BroadcastChannel('wwwhisper-login-success');
    broadcast.onmessage = function() {
      window.location.reload();
    }
  }

}());
