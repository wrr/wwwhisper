/*!
 * wwwhisper - web access control.
 */

/**
 * Injects wwwhisper sign out iframe into a body of a document.
 */
(function () {
  'use strict';

  function reposition() {
    // See https://developer.mozilla.org/en-US/docs/Web/API/Visual_Viewport_API

    // Tests and https://stackoverflow.com/a/44779316 indicate that scroll
    // event are already fired only during animation, so no need to throttle
    // with requestAnimationFrame.
    const viewport = window.visualViewport;
    const iframe = document.getElementById('wwwhisper-iframe');
    if (!iframe) {
      // Injected iframe can be removed dynamically when wwwhisper
      // backend communication fails.
      viewport.removeEventListener('scroll', reposition);
      viewport.removeEventListener('resize', reposition);
      return;
    }

    // With dynamic reposition iframe is placed relative to the
    // top left corner instead of the bottom right, in such way we
    // don't need to obtain layout viewport dimensions to calculate
    // offsets (no nice API for this, would require adding additional
    // div with 100% width & height).
    iframe.style.left =
      (viewport.offsetLeft + viewport.width - iframe.width).toString() + 'px';
    iframe.style.top =
      (viewport.offsetTop + viewport.height - iframe.height).toString() + 'px'

    // When scrolling it is not possible to update element position in
    // such a way that it stays completely fixed in the screen corner,
    // some flickering is visible. Adding animation masks this
    // flickering with a drawback that the element visibly detaches
    // from the corner during the scroll.
    iframe.style.transition = '0.02s ease';
  }

  function isDynamicRepositionNeeded(iframe) {
    // Fixed positioned iframe element is placed in the bottom right
    // corner of the layout viewport. On small screen mobile devices,
    // depending on the page style and "viewport" HTML meta tag,
    // layout viewport can be larger than visual viewport, making the
    // iframe not always visible. We detect such cases and reposition
    // the iframe dynamically with JS logic.
    const visualViewport = window.visualViewport;
    const iframeRect = iframe.getBoundingClientRect();
    return (visualViewport && (visualViewport.height < iframeRect.bottom ||
                               visualViewport.width < iframeRect.right));
  }
  function createIframe() {
    if (document.documentElement.clientWidth < 300) {
      // Screen too narrow.
      return;
    }
    const iframe = document.createElement('iframe');
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

    if (isDynamicRepositionNeeded(iframe)) {
      // See iframe.style.left comment in reposition().
      iframe.style.bottom = undefined;
      iframe.style.right = undefined;
      window.visualViewport.addEventListener('scroll', reposition);
      window.visualViewport.addEventListener('resize', reposition);
      // Set the initial position.
      reposition();
    }
  }

  // Do nothing if the current window is not the top level window (to
  // avoid having several overlays on the screen).
  if (window.parent === window) {
    window.addEventListener('load', createIframe());
  }
}());
