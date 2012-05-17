(function () {
  'use strict';
  var csrfToken, model, users, view, refresh;

  csrfToken = null;
  model = null;
  users = null;

  view = {
    locationPath : null,
    locationInfo : null,
    allowedUser : null,
    addLocation : null,
    user : null,
  };

  function inArray(value, array) {
    return ($.inArray(value, array) >= 0);
  }

  function removeFromArray(value, array) {
    var idx = $.inArray(value, array);
    if (idx === -1) {
      return;
    }
    array.splice(idx, 1);
  }

  function extractLocationsPaths(locations) {
    return $.map(locations, function(item) {
      return item.path;
    });
  }

  function allLocationsPaths() {
    return extractLocationsPaths(model.locations);
  }

  function accessibleLocationsPaths(userMail) {
    var accessibleLocations = $.grep(model.locations, function(location) {
      return inArray(userMail, location.allowedUsers);
    });
    return extractLocationsPaths(accessibleLocations);
  }

  function locationPathId(locationId) {
    return 'location' + locationId.toString();
  }

  function locationInfoId(locationId) {
    return 'resouce-info' + locationId.toString();
  }

  function findSelectLocationId() {
    return $('#location-list').find('.active').index();
  }

  // TODO: this no longer works, because addLocation call returns result.
  function mockAjaxCalls() {
    return model !== null && model.mockMode;
  }

  // TODO: remove duplication.
  function getCsrfToken(successCallback) {
    if (!mockAjaxCalls()) {
      $.ajax({
        url: '/auth/api/csrftoken/',
        type: 'GET',
        dataType: 'json',
        success: function(result) {
          csrfToken = result.csrfToken;
          successCallback();
        },
        error: function(jqXHR) {
          $('body').html(jqXHR.responseText);
        }
      })
    } else {
      csrfToken = "mockCsrfToken";
      successCallback();
    }
  }

  // TODO: Remove this one.
  function ajax(method, resource, params, successCallback) {
    if (!mockAjaxCalls()) {
      $.ajax({
        url: 'api/' + resource,
        type: method,
        data: JSON.stringify(params),
        //dataType: method === 'GET' ?  'json' : 'text',
        dataType: 'json',
        headers: {'X-CSRFToken' : csrfToken},
        success: successCallback,
        error: function(jqXHR) {
          // TODO: nice messages for user input related failures.
          $('body').html(jqXHR.responseText);
        }
      });
    } else {
      successCallback();
    }
  }

  function ajaxWithUrl(method, resource, params, successCallback) {
    var jsonData = null;
    if (params !== null) {
      jsonData = JSON.stringify(params);
    }

    if (!mockAjaxCalls()) {
      $.ajax({
        url: resource,
        type: method,
        data: jsonData,
        //dataType: method === 'GET' ?  'json' : 'text',
        dataType: 'json',
        headers: {'X-CSRFToken' : csrfToken},
        success: successCallback,
        error: function(jqXHR) {
          // TODO: nice messages for user input related failures.
          $('body').html(jqXHR.responseText);
        }
      });
    } else {
      successCallback();
    }
  }

  function getModel() {
    ajax('GET', 'model.json/', {}, function(result) {
      // TODO: parse json here.
      model = result;
      $('.locations-root').text(model.locationsRoot);
      refresh();
    });
  }

  function getUsers() {
    ajax('GET', 'users/', {}, function(result) {
      // TODO: parse json here.
      users = result.users;
      refresh();
    });
  }

  function addUser(userMail, onSuccessCallback) {
    ajax('POST', 'users/', {email: userMail},
         function(result) {
           users.push(result);
           refresh();
           onSuccessCallback();
         });
  }

  function removeUser(user) {
    ajaxWithUrl('DELETE', user.self, null,
         function() {
           $.each(model.locations, function(locationId, locationValue) {
             if (inArray(user.email, locationValue.allowedUsers)) {
               removeFromArray(userMail, locationValue.allowedUsers);
             }
           });
           removeFromArray(user, users);
           refresh();
         });
  }

  function allowAccessByUser(userMailArg, locationId) {
    var userMail, location, grantPermissionCallback;
    userMail = $.trim(userMailArg);
    location = model.locations[locationId];
    if (userMail.length === 0
        || inArray(userMail, model.locations[locationId].allowedUsers)) {
      return;
    }
    grantPermissionCallback = function() {
      ajax('PUT', 'permissions/', {email: userMail,
                                  path: location.path},
           function() {
             location.allowedUsers.push(userMail);
             refresh();
             $('#' + locationInfoId(locationId) + ' ' + '.add-allowed-user')
               .focus();
           });
    };

    if (!inArray(userMail, model.users)) {
      addUser(userMail, grantPermissionCallback);
    } else {
      grantPermissionCallback();
    }
  }

  // TODO: Fix assymetry (locationId above, location here).
  function revokeAccessByUser( userMail, location) {
    ajax('DELETE', 'permissions/', {email: userMail,
                                   path: location.path},
           function() {
             removeFromArray(userMail, location.allowedUsers);
             refresh();
           });
  }

  function addLocation(locationPathArg) {
    var locationPath = $.trim(locationPathArg);
    if (locationPath.length === 0
        || inArray(locationPath, allLocationsPaths())) {
      return;
    }
    ajax('PUT', 'locations/', {path: locationPath},
         function(escapedPath) {
           model.locations.push({
             'path': escapedPath,
             'allowedUsers': []
           });
           refresh();
           $('#add-location-input').focus();
         });
  }

  function removeLocation(locationId) {
    ajax('DELETE', 'locations/', {path: model.locations[locationId].path},
         function() {
           model.locations.splice(locationId, 1);
           var selectLocationId = findSelectLocationId();
           if (selectLocationId === locationId) {
             refresh(0);
           } else if (selectLocationId > locationId) {
             refresh(selectLocationId - 1);
           } else {
             refresh(selectLocationId);
           }
         });
  }

  function showLocationInfo(locationId) {
    $('#' + locationPathId(locationId)).addClass('active');
    $('#' + locationInfoId(locationId)).addClass('active');
  }

  function highlightAccessibleLocations(userMail) {
    $.each(model.locations, function(locationId, locationValue) {
      var id = '#' + locationPathId(locationId);
      if (inArray(userMail, locationValue.allowedUsers)) {
        $(id + ' a').addClass('accessible');
      } else {
        $(id + ' a').addClass('not-accessible');
      }
    });
  }

  function highlighLocationsOff() {
    $('#location-list a').removeClass('accessible');
    $('#location-list a').removeClass('not-accessible');
  }

  function showNotifyDialog(to, locations) {
    var body, website, locationsString, delimiter;
    if (locations.length === 0) {
      body = 'I have shared nothing with you. Enjoy.';
    } else {
      website = 'a website';
      if (locations.length > 1) {
        website = 'websites';
      }
      locationsString = $.map(locations, function(locationPath) {
        delimiter = (locationPath[0] !== '/') ? '/' : '';
        return 'https://' + model.locationsRoot + delimiter + locationPath;
      }).join('\n');

      body = 'I have shared ' + website + ' with you.\n'
        + 'Please visit:\n' + locationsString;
    }
    $('#notify-modal')
      .find('#notify-to').attr('value', to.join(', ')).end()
      .find('#notify-body').text(body).end()
      .modal('show');
  }

  function createLocationInfo(locationId, allowedUsers) {
    var locationInfo, allowedUserList;
    locationInfo = view.locationInfo.clone(true)
      .attr('id', locationInfoId(locationId))
      .find('.add-allowed-user')
      .change(function() {
        allowAccessByUser($(this).val(), locationId);
      })
      .typeahead({
        'source': model.users
      })
      .end();

    allowedUserList = locationInfo.find('.allowed-user-list');
    $.each(allowedUsers, function(userIdx, userMail) {
      view.allowedUser.clone(true)
        .find('.user-mail').text(userMail).end()
        .find('.remove-user').click(function() {
          revokeAccessByUser(userMail, model.locations[locationId]);
        }).end()
        .appendTo(allowedUserList);
    });
    locationInfo.appendTo('#location-info-list');
  }

  function showUsers() {
    var user;
    $.each(users, function(userIdx, userListItem) {
      user = view.user.clone(true);
      user.find('.user-mail').text(userListItem.email).end()
        .find('.remove-user').click(function() {
          removeUser(userListItem);
        }).end()
        .find('.highlight').hover(function() {
          highlightAccessibleLocations(userMail);
        }, highlighLocationsOff).end()
        .find('.notify').click(function() {
          showNotifyDialog([userMail], accessibleLocationsPaths(userMail));
        }).end()
        .appendTo('#user-list');
    });
  }

  function showLocations() {
    $.each(model.locations, function(locationId, locationValue) {
      view.locationPath.clone(true)
        .attr('id', locationPathId(locationId))
        .find('.url').attr('href', '#' + locationInfoId(locationId)).end()
        .find('.path').text(locationValue.path).end()
        .find('.remove-location').click(function(event) {
          // Do not show removed location info.
          event.preventDefault();
          removeLocation(locationId);
        }).end()
        .find('.notify').click(function() {
          showNotifyDialog(locationValue.allowedUsers, [locationValue.path]);
        }).end()
        .appendTo('#location-list');
      createLocationInfo(locationId, locationValue.allowedUsers);
    });
    view.addLocation.clone(true)
      .find('#add-location-input').typeahead({
        'source': allLocationsPaths()
      })
      .change(function() {
        addLocation($(this).val());
      }).end()
      .appendTo('#location-list');
  }

  refresh = function(selectLocationId) {
    if (typeof selectLocationId === 'undefined') {
      selectLocationId = findSelectLocationId();
    }
    if (selectLocationId === -1) {
      selectLocationId = 0;
    }

    $('#location-list').empty();
    $('#location-info-list').empty();
    $('#user-list').empty();

    showLocations();
    showUsers();

    showLocationInfo(selectLocationId);
  }


  $(document).ready(function() {
    view.locationPath = $('#location-list-item').clone(true);
    view.locationInfo = $('#location-info-list-item').clone(true);
    view.allowedUser = $('#allowed-user-list-item').clone(true);
    view.locationInfo.find('#allowed-user-list-item').remove();
    view.addLocation = $('#add-location').clone(true);
    view.user = $('.user-list-item').clone(true);

    getCsrfToken(function() {
      getModel();
      getUsers();
    })
  });

}());