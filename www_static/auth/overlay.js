/*!
 * wwwhisper - web access control.
 */

/**
 * If the user is authenticated, shows an overlay with the user's
 * email and a 'sign-out' button.
 */
(function () {
  'use strict';
  const net = new wwwhisper.Net(), MAX_EMAIL_LENGTH = 30;
  let broadcast;

  function getById(id) {
    return document.getElementById(id);
  }

  function navigateToGoodbye() {
    // Only pathname because login token doesn't preserve search and hash
    // URL parts (also passing hash would result in two hashes in the URL unless
    // the second hash is encoded).
    const back = window.top.location.pathname;
    window.top.location = '/wwwhisper/auth/goodbye#back=' + encodeURI(back);
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
    if (broadcast) {
      broadcast.postMessage('');
      broadcast.close();
    }
    navigateToGoodbye();
  }

  function logout() {
    net.ajax('POST', '/wwwhisper/auth/api/logout/', {}, logoutSucceeded);
  }

  function authenticated(result) {
    let emailToDisplay = result.email;
    if (emailToDisplay.length > MAX_EMAIL_LENGTH) {
      // Trim very long emails so 'sign out' button fits in
      // the iframe.
      emailToDisplay = result.email.substr(0, MAX_EMAIL_LENGTH) + '[...]';
    }
    getById('email').innerText = emailToDisplay;
    getById('wwwhisper-overlay').classList.remove('hide');
    getById('logout').addEventListener('click', logout);
    if (BroadcastChannel) {
      broadcast = new BroadcastChannel('wwwhisper-logout-success');
      broadcast.onmessage = function() {
        navigateToGoodbye();
      }
    }
  }

  net.ajax('GET', '/wwwhisper/auth/api/whoami/', null,
           // User is authenticated.
           authenticated,
           // User is not authenticated or some other error occurred.
           removeOverlay);
}());
