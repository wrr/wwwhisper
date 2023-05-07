/*!
 * wwwhisper - web access control.
 * Copyright (C) 2012-2023 Jan Wrobel
 */
(function () {
  'use strict';

  /**
   * Communicates with the server. Makes sure each request carries
   * cross site request forgery protection cookie. Serializes requests
   * parameters to JSON.
   */
  function Net() {
    var errorHandler = null, that = this;

    function error(errorHandlerArg, message, status, isTextPlain) {
      if (typeof errorHandlerArg !== 'undefined') {
        errorHandlerArg(message, status, isTextPlain);
      } else if (errorHandler !== null) {
        errorHandler(message, status, isTextPlain);
      } else {
        // No error handler. Fatal error.
        if (!isTextPlain) {
          message = 'Error.';
        }
        document.getElementsByTagName('html')[0].innerText = message;
      }
    }

    /**
     * Helper private function, in addition to all arguments accepted
     * by the public ajax() function, takes dictionary of headers to
     * be sent along with the request.
     */
    function ajaxCommon(method, resource, params, headersDict,
                        successCallback, errorHandlerArg) {
      var request = new XMLHttpRequest(), header, data = null;

      function onLoad() {
        var responseType, isTextResponse, isJsonResponse, responseData = null;
        responseType = (request.getResponseHeader('content-type') || '');

        if (200 <= request.status && request.status < 300) {
          isJsonResponse = (responseType.indexOf('application/json') !== -1);
          if (isJsonResponse) {
            responseData = JSON.parse(request.response);
          }
          successCallback(responseData);
        } else {
          isTextResponse = (responseType.indexOf('text/plain') !== -1);
          error(errorHandlerArg,
                request.responseText,
                request.status,
                isTextResponse);
        }
      }

      function onError() {
        error(errorHandlerArg, 'Failed to connect to the server', undefined,
              true);
      }

      function onAbort() {
        error(errorHandlerArg, 'Connection aborted', undefined, true);
      }

      request.open(method, resource, true);

      request.addEventListener('load', onLoad);
      request.addEventListener('error', onError);
      request.addEventListener('abort', onAbort);

      for (header in headersDict) {
        if (headersDict.hasOwnProperty(header)) {
          request.setRequestHeader(header, headersDict[header]);
        }
      }
      if (params !== null) {
        request.setRequestHeader('Content-Type',
                                 'application/json; charset=utf-8');
        data = JSON.stringify(params);
      }
      request.send(data);
    }

    function strip(str) {
      return str.replace(/^\s+|\s+$/g, '');
    }

    function getCookie(cookie_name) {
      var i, name, value, params, cookies = document.cookie.split(";");
      for (i = 0; i < cookies.length; i += 1) {
        params = cookies[i].split('=');
        if (params.length >= 2) {
          name = strip(params.shift());
          value = strip(params.shift());
          if (name == cookie_name) {
            return value;
          }
        }
      }
      return null;
    }

    /**
     * Retrieves csrf protection token and invokes a callback on
     * success.
     */
    function getCsrfToken(nextCallback, errorHandlerArg) {
      var token = getCookie('wwwhisper-csrftoken');
      if (token !== null) {
        // Token is set in a cookie.
        nextCallback(token);
      } else {
        // No token in a cookie, set it with an ajax call.
        ajaxCommon('GET', '/wwwhisper/auth/api/csrftoken/', null, null,
                   function(result) {
                     // Call succeeded, examine the cookie again.
                     token = getCookie('wwwhisper-csrftoken');
                     if (token !== null) {
                       nextCallback(token);
                     } else {
                       // This can happen if cookies are disabled.
                       error(errorHandlerArg, 'Failed to establish CSRF token',
                             undefined, true);
                     }
                   }, errorHandlerArg);
      }
    }

    /**
      * Invokes a given HTTP method (a string) on a given resource (a
      * string), passing to it parameters (an object that the function
      * serializes to json and that can be null). When successfully
      * done, invokes a successCallback.
      *
      * On failure, if an errorHandler is given as an argument or set
      * with setErrorHandler, invokes the handler and passes to it:
      *    +error message
      *    +HTTP error code
      *    +boolean flag indicating if the error message is textual
      *     (mime type text/plain).
      *
      * If an error handler is not defined, error is considered fatal:
      * current document message body is replaced with an error
      * message.
      */
    this.ajax = function(method, resource, params, successCallback,
                         errorHandlerArg) {
      getCsrfToken(function(csrfToken) {
        ajaxCommon(method, resource, params, {'X-CSRFToken' : csrfToken},
                   successCallback, errorHandlerArg);
      }, errorHandlerArg);
    };

    /**
     * Convenience method that registers a permanent callback to be
     * invoked when HTTP method returns an error. Useseful when the
     * same callback is used for many ajax() calls. Callback passed
     * directly to the ajax call takes precedence over the one set
     * with the setter.
     */
    this.setErrorHandler = function(handler) {
      errorHandler = handler;
    };
  }

  if (typeof(window.wwwhisper) === 'undefined'){
    window.wwwhisper = {};
  }
  window.wwwhisper.Net = Net;
}());
