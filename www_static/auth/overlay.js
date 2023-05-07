/*!
 * wwwhisper - web access control.
 */

/**
 * If the user is authenticated, shows an overlay with the user's
 * email and a 'sign-out' button.
 */
(function () {
  'use strict';
  var net = new wwwhisper.Net(), MAX_EMAIL_LENGTH = 30;

  function getById(id) {
    return document.getElementById(id);
  }

  /**
   * Removes the overlay. Keeping overlay hidden is not enough,
   * because all content below the iframe does not receive
   * user's input (e.g. links are non-clickable).
   */
  function removeOverlay() {
    window.parent.document.getElementById('wwwhisper-iframe').remove();
  }

  function logoutSucceeded() {
    window.top.location = '/wwwhisper/auth/goodbye.html';
  }

  function logout() {
    net.ajax('POST', '/wwwhisper/auth/api/logout/', {}, logoutSucceeded);
  }

  function authenticated(result) {
    var emailToDisplay = result.email;
    if (emailToDisplay.length > MAX_EMAIL_LENGTH) {
      // Trim very long emails so 'sign out' button fits in
      // the iframe.
      emailToDisplay = result.email.substr(0, MAX_EMAIL_LENGTH) + '[...]';
    }
    getById('email').innerText = emailToDisplay;
    getById('wwwhisper-overlay').classList.remove('hide');
    getById('logout').addEventListener('click', logout);
  }

  net.ajax('GET', '/wwwhisper/auth/api/whoami/', null,
           // User is authenticated.
           authenticated,
           // User is not authenticated or some other error occurred.
           removeOverlay);
}());
