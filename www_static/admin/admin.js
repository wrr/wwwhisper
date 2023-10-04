/*!
 * wwwhisper - web access control.
 * Copyright (C) 2012-2023 Jan Wrobel
 */
/*jslint browser: true, white: true, indent: 2 */
/*global  $ */
/*global wwwhisper */
(function () {
  'use strict';

  /**
   * Utility functions.
   */
  var utils = {

    /**
     * Throws if condition is false.
     */
    assert: function(condition, message) {
      function AssertionError(message) {
        this.message = message;
        this.toString = function() {
          return 'AssertionError: ' + this.message;
        };
      }

      if (!condition) {
        throw new AssertionError(message);
      }
    },

    /**
     * Calls callback for each element of an iterable.
     */
    each: function(iterable, callback) {
      $.each(iterable, function(id, value) {
        callback(value);
      });
    },

    /**
     * Finds an element in an array that satisfies a given
     * filter. Returns null if no such element exists.
     *
     * Filtering condition must be satisfied by at most one element,
     * if multiple elements satisfy the filter, AssertionError is
     * thrown.
     */
    findOnly: function(array, filterCallback) {
      var result;
      result = $.grep(array, filterCallback);
      if (result.length === 0) {
        return null;
      }
      utils.assert(result.length === 1,
                   'Not unique result of findOnly function.');
      return result[0];
    },

    /**
     * Returns true if a value is in an array.
     */
    inArray: function(value, array) {
      return ($.inArray(value, array) >= 0);
    },

    /**
     * Removes a value from an array, has no effect if the value is not
     * in an array.
     */
    removeFromArray: function(value, array) {
      var idx = $.inArray(value, array);
      if (idx === -1) {
        return;
      }
      array.splice(idx, 1);
    },

    /**
     * Comparison function to be used in sorting algorithms. Returns
     * -1, 0 or 1.
     */
    compare: function(a, b) {
      if (a < b) {
        return -1;
      }
      if (a > b) {
        return 1;
      }
      return 0;
    },

    /**
     * Returns array sorted in order defined by a given comparator (or
     * alphabetical if comparator is not passed). Does not modify the
     * input array.
     */
    sort: function(array, comparator) {
      var arrayCopy = array.slice(0, array.length);
      arrayCopy.sort(comparator);
      return arrayCopy;
    },

    /**
     * Returns array of object sorted by a property which name (a
     * string) is passed as an argument. Sort order is ascending. Each
     * object in the input array needs to have a property on which
     * sorting is done. Does not modify the input array.
     */
    sortByProperty: function(array, propertyName) {
      return utils.sort(array, function(a, b) {
        return utils.compare(a[propertyName], b[propertyName]);
      });
    },

    /**
     * Extracts a given property from each item of the input array and
     * returns these properties in the result array. Each item in the
     * input array needs to have the extracted property.
     */
    extractProperty: function(array, propertyName) {
      return $.map(array, function(item) {
        return item[propertyName];
      });
    },

    /**
     * Returns true if stringB is a prefix of stringA.
     */
    startsWith: function(stringA, stringB) {
      return stringA.lastIndexOf(stringB, 0) === 0;
    },

    /**
     * Extracts uuid from urn
     * (e.g. urn2uuid('urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a66')
     * === '6e8bc430-9c3a-11d9-9669-0800200c9a66').
     */
    urn2uuid: function(urn) {
      return urn.replace('urn:uuid:', '');
    },

    /**
     * Strips trailing /index.html or / from a given path. E.g:
     *   /foo/index.html -> /foo
     *   /foo/           -> /foo
     *   /foo            -> /foo
     */
    stripTrailingIndexHtmlAndSlash: function(path) {
      return path.replace(new RegExp('(/index.html$)|(/$)'), '');
    }
  };

  /**
   * Communicates with the server. Retrieves current access control
   * list and exposes operations to modify it (add/remove locations
   * and users, grant/revoke access to a location). Requests UI
   * updates when data to be displayed changes.
   */
  function Controller(ui, net) {
    var that = this;

    this.aliases = [];
    this.locations = [];
    var activeLocation = null;

    this.users = [];
    // Holds a wwwhisper login page configuration.
    this.skin = null;

    // An email of a currently signed in user that accesses the admin
    // application. This is kept to prevent the user from deleting a
    // permission that allows him to access the admin application.
    // Such operation is not illegal in itself and the back-end allows
    // it, but it is unlikely what the user would like to do (after
    // deleting the permission the admin application becomes unusable
    // for the user and only other admin user can fix it).
    this.adminUserEmail = null;
    // Path to the admin application
    this.adminPath = null;
    // Delegate errors to the UI.
    this.errorHandler = ui.handleError;

    this.getSortedLocations = function() {
      return utils.sortByProperty(this.locations, 'path');
    };

    this.getActiveLocation = function() {
      return activeLocation;
    };

    this.setActiveLocation = function(location) {
      activeLocation = location;
      ui.refresh();
    };

    this.isActiveLocation = function(location) {
      return (location === activeLocation);
    };

    function activateFirstLocation() {
      if (that.locations.length > 0) {
        activeLocation = that.getSortedLocations()[0];
      } else {
        activeLocation = null;
      }
    }

    /**
     * Returns true if a user can access a location.
     */
    this.canAccess = function(user, location) {
      return location.hasOwnProperty('openAccess') || utils.inArray(
        user.id, utils.extractProperty(location.allowedUsers, 'id'));
    };

    /**
     * Removes a user from an array of users that can access a given
     * location (this affect only a local representation of the
     * location object, nothing is sent to the server).
     */
    this.removeAllowedUser = function(user, location) {
      location.allowedUsers = $.grep(location.allowedUsers, function(u) {
        return u.id !== user.id;
      });
    };

    /**
     * Returns a user object with a given email or null.
     */
    this.findUserWithEmail = function(email) {
      return utils.findOnly(that.users, function(user) {
        return user.email === email;
      });
    };

    /**
     * Returns a location object with a given id or null.
     */
    this.findLocationWithId = function(id) {
      return utils.findOnly(that.locations, function(location) {
        return location.id === id;
      });
    };

    /**
     * Returns an array of locations that a given user can access.
     */
    this.accessibleLocations = function(user) {
      return $.grep(that.locations, function(location) {
        return that.canAccess(user, location);
      });
    };

    /**
     * Functions to retrieve arrays of users, locations and
     * aliases from the server. successCallback is invoked when
     * successfully done.
     */
    this.getUsers = function(successCallback) {
      net.ajax('GET', 'api/users/', null, function(result) {
        that.users = result.users;
        successCallback();
      });
    };
    this.getLocations = function(successCallback) {
      net.ajax('GET', 'api/locations/', null, function(result) {
        that.locations = result.locations;
        activateFirstLocation();
        successCallback();
      });
    };
    this.getAliases = function(successCallback) {
      net.ajax('GET', 'api/aliases/', null, function(result) {
        that.aliases = result.aliases;
        successCallback();
      });
    };
    this.getSkin = function(successCallback) {
      net.ajax('GET', 'api/skin/', null, function(result) {
        that.skin = result;
        successCallback();
      });
    };

    /**
     * Retrieves an email of currently signed in user, invokes
     * successCallback when successfully done. Displays warning if no user
     * is sign in, which means the admin interface is likely
     * misconfigured (can be accessed without authentication).
     */
    this.getAdminUser = function(successCallback) {
      // Do not use the default error handler, display a more
      // meaningful error message.
      net.ajax('GET', '/wwwhisper/auth/api/whoami/', null,
               function(result) {
                 that.adminUserEmail = result.email;
                 successCallback();
               },
               function(errorMessage, errorStatus, isTextPlain) {
                 if (errorStatus === 401) {
                   that.errorHandler(
                     'wwwhisper likely misconfigured: Admin application can ' +
                       'be accessed without authentication!');
                   successCallback();
                 } else {
                   that.errorHandler(errorMessage, errorStatus, isTextPlain);
                 }
               });
    };

    /**
     * Returns true if a path is handled by the admin application.
     */
    this.handledByAdmin = function(path) {
      return path === that.adminPath ||
        utils.startsWith(path, that.adminPath + '/');
    };

    /**
     * Executes all asynchronous tasks from the tasks array. Each task
     * is a function that needs to accept a single argument: a
     * callback to be asynchronously invoked on success. If all tasks
     * finish successfully, allDone callback is invoked.
     */
    this.asyncExecuteAll = function(tasks, allDone) {
      var succesful_cnt = 0;
      function done() {
        succesful_cnt += 1;
        if (succesful_cnt === tasks.length) {
          allDone();
        }
      }
      utils.each(tasks, function(task) {
        task(done);
      });
    };

    /**
     * Adds an alias (scheme://domain[:optional port]) that can be
     * used to access the site.
     */
    this.addAlias = function(urlArg) {
      net.ajax('POST', 'api/aliases/', {url: urlArg},
               function(alias) {
                 that.aliases.push(alias);
                 ui.refresh();
               });
    };

    this.removeAlias = function(alias, failureHandler) {
      net.ajax('DELETE', alias.self, null,
               function() {
                 utils.removeFromArray(alias, that.aliases);
                 ui.refresh();
               },
               failureHandler);
    };

    /**
     * Adds a location with a given path.
     *
     * Refuses to add sub location to the admin application (this is
     * just a client side check to prevent the user from shooting
     * himself in the foot).
     */
    this.addLocation = function(locationPathArg) {
      var locationPath = $.trim(locationPathArg);
      if (that.handledByAdmin(locationPath)) {
        that.errorHandler(
          'Adding sublocations to admin is not supported '+
            '(It could easily cut off access to the admin application).');
        return;
      }
      net.ajax('POST', 'api/locations/', {path: locationPath},
               function(newLocation) {
                 that.locations.push(newLocation);
                 activeLocation = newLocation;
                 ui.refresh();
               });
    };

    this.removeLocation = function(location, failureHandler) {
      net.ajax('DELETE', location.self, null,
               function() {
                 utils.removeFromArray(location, that.locations);
                 if (location === activeLocation) {
                   activateFirstLocation();
                 }
                 ui.refresh();
               },
               failureHandler);
    };

    /**
     * Adds a user with a given email. Invokes a callback on success.
     */
    this.addUser = function(emailArg, successCallback) {
      net.ajax('POST', 'api/users/', {email: emailArg},
               function(user) {
                 that.users.push(user);
                 successCallback(user);
               });
    };

    this.removeUser = function(user, failureHandler) {
      net.ajax('DELETE', user.self, null,
               function() {
                 utils.each(that.locations, function(location) {
                   if (that.canAccess(user, location)) {
                     that.removeAllowedUser(user, location);
                   }
                 });
                 utils.removeFromArray(user, that.users);
                 ui.refresh();
               },
               failureHandler);
    };

    /**
     * Allows everyone access to a location.
     */
    this.grantOpenAccess = function(location) {
      net.ajax(
        'PUT',
        location.self + 'open-access/',
        null,
        function(result) {
          location.openAccess = result;
          ui.refresh();
        }
      );
    };

    /**
     * Turns on normal access control for a location (only explicitly
     * listed users are granted access).
     */
    this.revokeOpenAccess = function(location) {
      if (!location.hasOwnProperty('openAccess')) {
        return;
      }
      net.ajax(
        'DELETE',
        location.self + 'open-access/',
        null,
        function() {
          delete location.openAccess;
          ui.refresh();
        }
      );
    };

    /**
     * Grants a user with a given email access to a given location.
     *
     * Is user with such email does not exist, adds the user first.
     */
    this.grantAccess = function(email, location, failureHandler) {
      var cleanedEmail, user, grantPermissionCallback;
      cleanedEmail = $.trim(email);
      if (cleanedEmail.length === 0) {
        return;
      }

      user = that.findUserWithEmail(cleanedEmail);
      if (user !== null && that.canAccess(user, location)) {
        // User already can access the location.
        return;
      }

      grantPermissionCallback = function(userArg) {
        net.ajax(
          'PUT',
          location.self + 'allowed-users/' + utils.urn2uuid(userArg.id) + '/',
          null,
          function() {
            // Do nothing if the user was granted access in the
            // meantime (this can happen for instance when grant
            // access is clicked twice).
            if (!that.canAccess(userArg, location)) {
              location.allowedUsers.push(userArg);
              ui.refresh();
            }
          },
          failureHandler
        );
      };

      if (user !== null) {
        grantPermissionCallback(user);
      } else {
        that.addUser(cleanedEmail, grantPermissionCallback);
      }
    };

    /**
     * Revokes access to a given location by a given user.
     */
    this.revokeAccess = function(user, location, failureHandler) {
      net.ajax(
        'DELETE',
        location.self + 'allowed-users/' + utils.urn2uuid(user.id) + '/',
        null,
        function() {
          that.removeAllowedUser(user, location);
          ui.refresh();
        },
        failureHandler);
    };

    this.updateSkin = function(newSkin) {
      net.ajax('PUT', 'api/skin/', newSkin,
               function(result) {
                 that.skin = result;
                 ui.refresh();
               });
    };

    /**
     * Activates the admin application (retrieves all dynamic data
     * from the server and refreshes the UI).
     */
    this.activate = function() {
      that.adminPath = utils.stripTrailingIndexHtmlAndSlash(
        window.location.pathname);
      net.setErrorHandler(that.errorHandler);
      that.asyncExecuteAll([that.getLocations,
                            that.getUsers,
                            that.getAliases,
                            that.getSkin,
                            that.getAdminUser],
                           ui.refresh);
    };
  }

  /**
   * Handles user interface. Reacts to the user input and dispatches
   * appropriate access management operations to the Controller
   * object.
   */
  function UI() {

    // Cloned parts of a DOM tree, responsible for displaying and
    // manipulating access control list. The structure is defined in
    // the html file, this way js code does not need to create complex
    // DOM 'manually'.
    var view = {
      // A path to a location + controls to remove and visit a location.
      locationPath : $('.location-list-item').clone(true),
      // A list of users that can access a location (contains
      // view.allowedUser elements) + input box for adding a new user.
      locationInfo : $('#location-info').clone(true)
        .find('.add-allowed-user').val('').end(), //Clears any stored input.
      // A single user that is allowed to access a location + control
      // to revoke access.
      allowedUser : $('.allowed-user-list-item').clone(true),
      // An input box for adding a new location.
      addLocation : $('#add-location').clone(true)
        .find('#add-location-input').val('').end(),
      // User who was granted access to some location at some point +
      // controls to remove the user (alongwith access to all
      // locations) and grant access to currently active location.
      user : $('.user-list-item').clone(true),
      alias : $('.alias-list-item').clone(true),
      // Box for displaying error messages.
      errorMessage : $('.alert-danger').first().clone(true)
    },
    that = this,
    controller = null,
    loading = true,
    ENTER_KEY = 13;

    /**
     * scheme://domain[:port if not default] of the current document.
     */
    function currentUrlRoot() {
      return location.protocol + '//' + location.host;
    }

    /**
     * Annotates currently signed in user to make it clearer that this
     * user is treated a little specially (can not be removed, can not
     * be revoked access to the admin location).
     */
    function userAnnotation(user) {
      if (user.email === controller.adminUserEmail) {
        return ' (you)';
      }
      return '';
    }

    /**
     * Annotates a current url on the list of aliases.
     */
    function aliasAnnotation(alias) {
      if (alias.url === currentUrlRoot()) {
        return ' (current)';
      }
      return '';
    }

    function focusedElement() {
      return $(document.activeElement);
    }

    /**
     * Returns id of a DOM element responsible for displaying a given
     * location path (clone of the view.locationPath).
     */
    function locationPathId(location) {
      return 'location-' + utils.urn2uuid(location.id);
    }

    /**
     * Returns id of a DOM element responsible for displaying a list
     * of users allowed to access a given location (clone of the
     * view.locationInfo).
     */
    function locationInfoId(location) {
      return 'location-info-' + utils.urn2uuid(location.id);
    }

    /**
     * Returns id of an input box responsible for adding emails of
     * users allowed to access a given location.
     */
    function addAllowedUserInputId(location) {
      return 'add-allowed-user-input-' + utils.urn2uuid(location.id);
    }

    function grantAccess(userId, location) {
      if (userId === '*') {
        controller.grantOpenAccess(location);
      } else {
        // Allow to enter multiple emails separated by ';'.
        utils.each(userId.split(/[;\s]+/), function(email) {
          if (email !== '') {
            controller.grantAccess(email, location);
          }
        });
      }
    }

    function inProgress(element, cssClass) {
      element.closest('div').addClass('invisible');
      element.closest('li').addClass(cssClass);
    }

    function failedHandler(element, cssClass) {
      return function(message, status, isTextPlain) {
        element.closes('li').removeClass(cssClass);
        element.closes('div').addClass('visibility', 'visible');
        that.handleError(message, status, isTextPlain);
      };
    }

    function removeInProgress(element) {
      inProgress(element, 'removing');
    }

    function removeFailedHandler(element) {
      return failedHandler(element, 'removing');
    }

    function grantingInProgress(element) {
      inProgress(element, 'granting');
    }

    function grantFailedHandler(element) {
      return failedHandler(element, 'granting');
    }

    /**
     * Creates a DOM subtree to handle an active location. The subtree
     * contains emails of allowed users, an input box to grant access
     * to a new user, controls to revoke access from a particular
     * user.
     */
    function showLocationInfo(location) {
      var locationView, allowedUserList, isAdminLocation;

      isAdminLocation = controller.handledByAdmin(location.path);

      locationView = view.locationInfo.clone(true)
        .attr('id', locationInfoId(location))
        .attr('location-urn', location.id)
        .find('.add-allowed-user')
        .attr('id', addAllowedUserInputId(location))
        .keyup(function(event) {
          var userId = $.trim($(this).val());
          if (event.which === ENTER_KEY) {
            grantAccess(userId, location);
            userId = '';
            $(this).val(userId);
          }
          if (userId !== '') {
            $(this).siblings('button').removeClass('disabled');
          } else {
            $(this).siblings('button').addClass('disabled');
          }
        })
        .end()
        .find('button').click(function() {
          var input = $(this).siblings('input'), userId = $.trim(input.val());
          grantAccess(userId, location);
          input.val('');
          $(this).addClass('disabled');
        })
        .end();

      allowedUserList = locationView.find('.allowed-user-list');
      if (location.hasOwnProperty('openAccess')) {
        // Disable entering email addresses of allowed user: everyone
        // is allowed.
        locationView.find('.add-allowed-user')
          .attr('placeholder', 'Everyone is allowed to access the location')
          .attr('disabled', true);

        view.allowedUser.clone(true)
          .find('.user-mail').text('*')
          .end()
          .find('.unshare').click(function() {
            controller.revokeOpenAccess(location);
          })
          .end()
          .appendTo(allowedUserList);
      } else {
        // When the first location on the list is disabled and the
        // page is refreshed, all locations become
        // disabled. Placeholder text is valid for them so it doesn't
        // seem like the first location is cloned.
        locationView.find('.add-allowed-user').attr('disabled', false);

        utils.each(
          utils.sortByProperty(location.allowedUsers, 'email'), function(user) {
            var isAdminUser = (user.email === controller.adminUserEmail);
            view.allowedUser.clone(true)
              .find('.user-mail').text(user.email + userAnnotation(user))
              .end()
              .find('.unshare').click(function() {
                removeInProgress($(this));
                controller.revokeAccess(
                  user, location, removeFailedHandler($(this)));
              })
              // Protect the currently signed-in user from disallowing
              // herself access to the admin application.
              .addClass(isAdminLocation && isAdminUser ? 'invisible' : null)
              .end()
              .appendTo(allowedUserList);
          });
      }
      locationView.appendTo('#location-info-container');

      // Break circular references.
      locationView = null;
      allowedUserList = null;
    }

    function showLocation(location) {
      var pathView, isAdminLocation;
      isAdminLocation = controller.handledByAdmin(location.path);

      pathView = view.locationPath.clone(true)
        .click(function() {
          controller.setActiveLocation(location);
        })
        .attr('id', locationPathId(location))
        .attr('location-urn', location.id)
        .find('.url').attr(
          'href', '#' + locationInfoId(location))
        .end()
        .find('.path').text(location.path)
        .end()
        .find('.remove-location').click(function(event) {
          removeInProgress($(this));
          controller.removeLocation(location, removeFailedHandler($(this)));
          // Do not propagate the event (not to show removed location info):
          return false;
        })
         // Do not allow admin location to be removed.
        .addClass(isAdminLocation ? 'invisible' : null)
        .end()
        .find('.view-page').click(function() {
          window.open(location.path, '_blank');
        })
        .end()
        .appendTo('#location-list');
      if (controller.isActiveLocation(location)) {
        pathView.addClass('active');
      }
      pathView = null;
      isAdminLocation = null;
    }

    /**
     * Creates a DOM subtree to handle a list of locations. The
     * subtree contains locations' paths, controls to add/remove a
     * location and a link to visit a location with a browser. For a
     * currently active location more details are visible (created
     * with the showLocationInfo function).
     */
    function showLocationsList(activeLocation) {
      utils.each(controller.getSortedLocations(), showLocation);

      view.addLocation.clone(true)
        .find('#add-location-input')
        .keyup(function(event) {
          var path = $.trim($(this).val());
          if (event.which === ENTER_KEY) {
            if (path !== '') {
              controller.addLocation(path);
            }
            path = '';
            $(this).val(path);
          }
          if (path === '') {
            $('#add-location-button').addClass('disabled');
          } else {
            $('#add-location-button').removeClass('disabled');
          }
        })
        .end()
        .find('#add-location-button')
        .click(function() {
          var input = $('#add-location-input'), path = $.trim(input.val());
          if (path !== '') {
            controller.addLocation(path);
          }
          input.val('');
          $(this).addClass('disabled');
        })
        .end()
        .appendTo('#location-container');

      if (activeLocation !== null) {
        showLocationInfo(activeLocation);
      }
    }

    function showAlias(alias) {
      var aliasView = view.alias.clone(true),
      isCurrentUrl = (alias.url === currentUrlRoot());

      aliasView.find('.url').text(alias.url + aliasAnnotation(alias))
        .end()
        .find('.remove-alias').click(function(event) {
          removeInProgress($(this));
          controller.removeAlias(alias, removeFailedHandler($(this)));
          return false;
        })
        .addClass(isCurrentUrl ? 'invisible' : null)
        .end()
        .find('.view-page').click(function() {
          window.open(alias.url,'_blank');
        })
        .end()
        .appendTo('#alias-list');
      aliasView = null;
    }

    function showAliasesList() {
      utils.each(utils.sort(controller.aliases, function(a, b) {
        var partsA = a.url.split('://'),
        partsB = b.url.split('://'),
        result = utils.compare(partsA[1], partsB[1]);
        if (result === 0) {
          // Domains are the same, compare schemes.
          return utils.compare(partsA[0], partsB[0]);
        }
        return result;
      }), showAlias);

      function addAliasCommon(url) {
        var input = $('#add-alias-input');
        url = $.trim(input.val());
        if (url !== '') {
          controller.addAlias($('#add-alias-scheme').val() + url);
        }
        input.val('');
        $('#add-alias-button').addClass('disabled');
      }

      $('#add-alias-input')
        .keyup(function(event) {
          if (event.which === ENTER_KEY) {
            addAliasCommon();
          } else if ($(this).val() === '') {
            $('#add-alias-button').addClass('disabled');
          } else {
            $('#add-alias-button').removeClass('disabled');
          }
        })
        .end();
      $('#add-alias-button')
        .click(addAliasCommon)
        .end();
    }

    function showUser(user, activeLocation) {
      const userView = view.user.clone(true);

      if (activeLocation !== null &&
          !controller.canAccess(user, activeLocation)) {
        userView.find('.share')
          .removeClass('invisible')
          .click(function() {
            grantingInProgress($(this));
            controller.grantAccess(
              user.email, activeLocation, grantFailedHandler($(this)));
          });
      }

      const isAdminUser = (user.email === controller.adminUserEmail);
      userView
        .find('.user-mail')
        .text(user.email + userAnnotation(user))
        .end()
        .find('.remove-user').click(function() {
          removeInProgress($(this));
          controller.removeUser(user, removeFailedHandler($(this)));
        })
      // Do not allow currently signed-in user to delete herself
      // (this is only UI enforced, from a server perspective such
      // operation is OK).
        .addClass(isAdminUser ? 'invisible' : null)
        .end()
        .appendTo('#user-list');
    }

    /**
     * Creates a DOM subtree to handle a list of known users. The
     * subtree contains an email of each user and controls to remove a
     * user and to grant a user access to a currently active location
     * (this control is visible only if the user can not already
     * access the location).
     */
    function showUsersList(activeLocation) {
      utils.each(utils.sortByProperty(controller.users, 'email'),
                 function(user) {
                   showUser(user, activeLocation);
                 });
    }

    /**
     * Enables a 'Save' button if any site customization inputs are
     * changed, otherwise disables the button.
     */
    function toggleSaveButton() {
      let saveNeeded = false;
      for (let formId of ['title', 'header', 'message']) {
        if ($('#' + formId).val() !== controller.skin[formId]) {
          saveNeeded = true;
          break;
        }
      }
      if (!saveNeeded) {
        saveNeeded = (
          $('#branding').prop('checked') !== controller.skin.branding);
      }
      if (saveNeeded) {
        $('#custom-login-save').removeClass('disabled');
      } else {
        $('#custom-login-save').addClass('disabled');
      }
    }

    /**
     * Configures controls to customize the wwwhisper login page.
     */
    function showCustomizeLogin() {
      $('#custom-login input:text').each(function() {
        var field = $(this).attr('id');
        $(this).val(controller.skin[field]);
        $(this).change(toggleSaveButton);
        // Redundant, but for input fields change() is not fired until
        // focus is changed, and keyup() is not fired when the input is
        // changes with a mouse (for example on copy-paste).
        $(this).keyup(toggleSaveButton);
      });
      $('#branding').prop('checked', controller.skin.branding)
        .change(toggleSaveButton);
      toggleSaveButton();
    }

    function saveCusomizedLogin() {
      var skin = {};
      $('#custom-login input:text').each(function() {
        var field = $(this).attr('id');
        skin[field] = $(this).val();
      });
      skin.branding = $('#branding').prop('checked');
      controller.updateSkin(skin);
    }

    /**
     * Returns a hash part of the current url (without '#') or 'acl'
     * if the hash part is empty.
     */
    function activeHash() {
      var hash = location.hash.replace(/^#/, '');
      if (loading) {
        return 'loading';
      }
      if (hash === '' || hash === null) {
        return 'acl';
      }
      return hash;
    }

    /**
     * Changes the main content that is displayed on the screen
     * (access control UI or site settings etc.).
     *
     * Highlights the relevant link in the top navigation bar.
     */
    function showContainer(containerClass) {
      $('.nav-content').addClass('hide');
      $('.nav-content.' + containerClass).removeClass('hide');
      $('.navbar-nav > a').removeClass('active');
      $('.navbar-nav > a.' + containerClass).addClass('active');
    }

    function showContainerPointedByHash() {
      showContainer(activeHash());
    }

    function hashChanged() {
      showContainerPointedByHash();
      that.refresh();
    }

    /**
     * Provides a basic support for browsers that do not expose
     * hashchanged event. Containers are changed only on menu clicks
     * (back, forward buttons are not supported).
     */
    function hashClickedHandler(hash) {
      return function() {
        showContainer(hash);
        that.refresh();
      };
    }

    /**
     * Handles errors. Not HTTP related errors (status undefined)
     * or HTTP errors with plain text messages are displayed and
     * automatically hidden after some time.
     *
     * Authentication needed error (401) indicates that the user
     * signed-out - admin page is reloaded to show a login prompt.
     *
     * Errors without plain text messages are considered fatal -
     * received error message replaces the current document.
     */
    this.handleError = function(message, status, isTextPlain) {
      // Scroll to make sure error is visible.
      window.scroll({
        top: 0,
        left: 0,
        behavior: 'smooth',
      });

      if (status === undefined || status === 401 || isTextPlain) {
        var error = view.errorMessage.clone(true);

        if (status === 401) {
          // User signed out, reload the admin page.
          window.location.reload(true);
        }

        error.removeClass('hide')
          .find('.alert-message')
          .text(message)
          .end()
          .appendTo('.' + activeHash() +  ' > .error-box');

        window.setTimeout(function() {
          error.alert('close');
        }, 15000);
      } else {
        // Fatal error.
        $('html').html(message);
      }
    };

    /**
     * Refreshes all controls. Displayed data (with the exception of
     * an error message) is never updated partially. All UI elements
     * are cleared and recreated. If locationToActivate is given, it
     * becomes activated, otherwise currently active location stays
     * active or if none, the first location in alphabetical order.
     */
    this.refresh = function() {
      var focusedElementId, activeLocation = controller.getActiveLocation(),
      scrollTop = $(document).scrollTop(),
      scrollLeft = $(document).scrollLeft();

      loading = false;

      showContainerPointedByHash();

      focusedElementId = focusedElement().attr('id');

      $('#alias-list').empty();
      $('#location-list').empty();
      $('#add-location').remove();
      $('#location-info-container').empty();
      $('#user-list').empty();
      $('.active-location').text(activeLocation.path);

      showAliasesList(activeLocation);
      showLocationsList(activeLocation);
      showUsersList(activeLocation);
      showCustomizeLogin();

      if (focusedElementId) {
        $('#' + focusedElementId).focus();
      }

      // Rewind a document to where it was.
      window.scroll({
        top: scrollTop,
        left: scrollLeft,
        behavior: 'instant',
      });
    };

    /**
     * Must be called before the first call to refresh().
     */
    this.setController = function(controllerArg) {
      controller = controllerArg;
    };

    /**
     * Initializes the UI.
     */
    function initialize() {
      // locationInfo contains a single allowed user element from the
      // html document. Remove it.
      view.locationInfo.find('.allowed-user-list-item').remove();


      // Configure static help messages.
      $('.help').click(function() {
        if ($('.help-message').hasClass('hide')) {
          $('.help-message').removeClass('hide');
          $('.help').text('Hide help');
        } else {
          $('.help-message').addClass('hide');
          $('.help').text('Show help');
        }
      });
      if (window.onhashchange !== undefined) {
        $(window).on('hashchange', hashChanged);
      } else {
        // Dinosaur browsers.
        $('.acl').click(hashClickedHandler('acl'));
        $('.settings').click(hashClickedHandler('settings'));
      }
      $('#custom-login-save').click(saveCusomizedLogin);
    }
    initialize();
  }

  function initialize() {
    var ui, net, controller;
    // UI depends on controller, but can be created without it.
    ui = new UI();
    net = new wwwhisper.Net(ui);
    controller = new Controller(ui, net);
    ui.setController(controller);
    controller.activate();
  }

  if (window.ExposeForTests) {
    // For qunit tests, expose objects to be tested.
    window.utils = utils;
    window.Controller = Controller;
  } else {
    initialize();
  }
}());
