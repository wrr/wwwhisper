/*!
 * wwwhisper - web access control.
 */

/**
 * Injects wwwhisper sign out iframe into a body of a document.
 */
(function () {
  'use strict';

  function createIframe() {
    if (window.innerWidth < 300) {
      // Screen too narrow.
      return;
    }
    var iframe = document.createElement('iframe');
    iframe.id = 'wwwhisper-iframe';
    iframe.src = '/wwwhisper/auth/overlay.html';
    iframe.width = Math.min(window.innerWidth, 340);
    iframe.height = 30;
    iframe.allowTransparency = 'true';
    iframe.frameBorder = '0';
    iframe.scrolling = 'no';
    iframe.style.position = 'fixed';
    iframe.style.overflow = 'hidden';
    iframe.style.border = '0px';
    iframe.style.bottom = '0px';
    iframe.style.right = '0px';
    iframe.style.zIndex = '11235';
    iframe.style.backgroundColor = 'transparent';
    document.body.appendChild(iframe);
  }

  // Do nothing if the current window is not the top level window (to
  // avoid having several overlays on the screen).
  if (window.parent === window) {
    window.addEventListener('load', createIframe());
  }
}());
