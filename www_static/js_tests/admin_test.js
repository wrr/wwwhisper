/*!
 * wwwhisper - web access control.
 * Copyright (C) 2012-2023 Jan Wrobel
 */
(function() {
  'use strict';

  var mock_net, mock_ui, controller;

  function MockNet() {
    var expectedCalls = [];

    this.ajax = function(method, resource, params, successCallback) {
      var expectedCall;
      if (expectedCalls.length === 0) {
        ok(false, 'Unexpected ajax call ' + method + ' ' + resource);
      } else {
        expectedCall = expectedCalls.shift();
        deepEqual(method, expectedCall.method, 'HTTP method' );
        deepEqual(resource, expectedCall.resource, 'HTTP resource');
        deepEqual(params, expectedCall.params, 'HTTP method params');
        successCallback(expectedCall.result);
      }
    };

    this.expectAjaxCall = function(
      methodArg, resourceArg, paramsArg, resultArg) {
      expectedCalls.push({
        method: methodArg,
        resource: resourceArg,
        params: paramsArg,
        result: resultArg
      });
    };

    this.verify = function() {
      ok(expectedCalls.length === 0, 'All expected ajax calls invoked.');
    };

    this.setErrorHandler = function() {}
  }

  function MockUI(controller) {
    var that = this;
    this.lastError = null;

    this.refresh = function() {};
    this.handleError = function(message, status) {
      that.lastError = message;
    };
  }

  QUnit.testStart = function() {
    mock_net = new MockNet();
    mock_ui = new MockUI();
    controller = new Controller(mock_ui, mock_net);
  };

  module('Utility functions');

  test('assert', function() {
    utils.assert(true, "Should not throw.");
    throws(function() {
      utils.assert(false, "Should throw.");
    });
  });

  test('each', function() {
    var sum = 0;
    utils.each([1, 1, 2, 3, 5], function(x) {
      sum += x;
    });
    deepEqual(sum, 12);
    utils.each([], function(x) {
      ok(false);
    });
  });

  test('findOnly', function() {
    deepEqual(utils.findOnly([[1, 2], [2, 3], [4, 5], [5, 6]],
                             function(x) {
                               return x[0] === 4;
                             }), [4, 5]);

    deepEqual(utils.findOnly([1, 2, 3, 4, 5],
                             function(x) {
                               return x === 6;
                             }), null);
    throws(function() {
      utils.findOnly([1, 2, 3, 1],
                     function(x) {
                       return x === 1;
                     });
    });
  });

  test('inArray', function() {
    ok(utils.inArray(2, [1, 2, 3]));
    ok(utils.inArray('a', ['a', 'b', 'c']));
    ok(utils.inArray('foo', ['bar', 'baz', 'foo']));
    ok(utils.inArray('foo', ['foo', 'foo', 'foo']));
    ok(utils.inArray(true, [true]));

    ok(!utils.inArray('foo', []));
    ok(!utils.inArray('foo', ['fooz']));
    ok(!utils.inArray(1, [[1], 2, 3]));
  });

  test('removeFromArray', function() {
    var array = ['aa', 'bb', 'cc'];
    utils.removeFromArray('bb', array);
    deepEqual(array, ['aa', 'cc']);
    utils.removeFromArray('cc', array);
    deepEqual(array, ['aa']);
    utils.removeFromArray('a', array);
    deepEqual(array, ['aa']);
    utils.removeFromArray('aa', array);
    deepEqual(array, []);
    utils.removeFromArray(null, array);
    deepEqual(array, []);
  });

  test('compare', function() {
    deepEqual(utils.compare('ab', 'ac'), -1);
    deepEqual(utils.compare('ab', 'ab'), 0);
    deepEqual(utils.compare('ab', 'aa'), 1);
  });

  test('sort', function() {
    var array = ['b', 'aa', 'a', 'z'];
    deepEqual(utils.sort(array), ['a', 'aa', 'b', 'z']);
    // Sort should not modify the input array.
    deepEqual(array, ['b', 'aa', 'a', 'z']);
    deepEqual(utils.sort([]), []);
  });

  test('sortByProperty', function() {
    var array = [{f1: 'a', f2: 'b'},
                 {f1: 'b', f2: 'aa'},
                 {f1: 'c', f2: 'a'},
                 {f1: 'd', f2: 'z'}];
    deepEqual(utils.sortByProperty(array, 'f2'),
             [{f1: 'c', f2: 'a'},
              {f1: 'b', f2: 'aa'},
              {f1: 'a', f2: 'b'},
              {f1: 'd', f2: 'z'}]);
    deepEqual(utils.sortByProperty(array, 'f1'), array);
  });

  test('extractProperty', function() {
    var array = [{f1: 'a', f2: 'b'},
                 {f1: 'b', f2: 'aa'},
                 {f1: 'c', f2: 'a'},
                 {f1: 'd', f2: 'z'}];
    deepEqual(utils.extractProperty(array, 'f2'),
              ['b', 'aa', 'a', 'z']);
  });

  test('startsWith', function() {
    ok(utils.startsWith('foobar', 'foo'));
    ok(utils.startsWith('foo', 'foo'));
    ok(utils.startsWith('', ''));
    ok(!utils.startsWith('foo', 'foobar'));
    ok(!utils.startsWith('barfoo', 'foo'));
  });

  test('urn2uuid', function() {
    deepEqual(
      utils.urn2uuid('urn:uuid:41be0192-0fcc-4a9c-935d-69243b75533c'),
      '41be0192-0fcc-4a9c-935d-69243b75533c');
  });

  test('stripTrailingIndexHtmlAndSlash', function() {
    deepEqual(utils.stripTrailingIndexHtmlAndSlash('/foo/index.html'), '/foo');
    deepEqual(utils.stripTrailingIndexHtmlAndSlash('/index.html/bar'),
              '/index.html/bar');
    deepEqual(utils.stripTrailingIndexHtmlAndSlash('/foo/'), '/foo');
    deepEqual(utils.stripTrailingIndexHtmlAndSlash('/foo'), '/foo');
    deepEqual(utils.stripTrailingIndexHtmlAndSlash('/foo/bar'), '/foo/bar');
  });

  module('Controller');

  test('canAccess', function() {
    ok(controller.canAccess(
      {
        id: 'userA',
        email: 'foo@example.com'
      },
      {
        id: '12',
        path: '/foo',
        allowedUsers: [
          {
            email: 'foo@example.com',
            id: 'userA'
          },
          {
            email: 'bar@example.com',
            id: 'userB'
          }
        ]
      }));

    ok(!controller.canAccess(
      {
        id: 'userC',
        email: 'foo@example.com'
      },
      {
        id: '12',
        path: '/foo',
        allowedUsers: [
          {
            email: 'foo@example.com',
            id: 'userA'
          },
          {
            email: 'bar@example.com',
            id: 'userB'
          }
        ]
      }));
  });

  test('removeAllowedUser', function() {
    var location, userA, userB;
    userA = {
      email: 'foo@example.com',
      id: 'userA'
    };
    userB = {
      email: 'bar@example.com',
      id: 'userB'
    };
    location = {
      id: '12',
      path: '/foo',
      allowedUsers: [
        userA,
        userB
      ]
    };
    ok(controller.canAccess(userA, location));
    ok(controller.canAccess(userB, location));
    controller.removeAllowedUser(userB, location);
    ok(controller.canAccess(userA, location));
    ok(!controller.canAccess(userB, location));
  });

  test('findUserWithEmail', function() {
    var userA, userB;
    userA = {
      email: 'foo@example.com',
      id: 'userA'
    };
    userB = {
      email: 'bar@example.com',
      id: 'userB'
    };
    controller.users.push(userA);
    controller.users.push(userB);
    deepEqual(controller.findUserWithEmail('bar@example.com'), userB);
    deepEqual(controller.findUserWithEmail('baz@example.com'), null);
  });

  test('findLocationWithId', function() {
    var locationA, locationB;
    locationA = {
      path: '/foo',
      id: 'locationA'
    };
    locationB = {
      path: '/foo/bar',
      id: 'locationB'
    };
    controller.locations.push(locationA);
    controller.locations.push(locationB);
    deepEqual(controller.findLocationWithId('locationB'), locationB);
    deepEqual(controller.findLocationWithId('locationC'), null);
  });

  test('accessibleLocations', function() {
    var locationA, locationB, userA, userB, userC;
    userA = {
      email: 'foo@example.com',
      id: 'userA'
    };
    userB = {
      email: 'bar@example.com',
      id: 'userB'
    };
    userC = {
      email: 'baz@example.com',
      id: 'userC'
    };
    controller.users = [userA, userB, userC];

    locationA = {
      id: '12',
      path: '/foo',
      allowedUsers: [
        userA,
        userB
      ]
    };
    locationB = {
      id: '13',
      path: '/foo/bar',
      allowedUsers: [
        userB
      ]
    };
    controller.locations = [locationA, locationB];

    deepEqual(controller.accessibleLocations(userA), [locationA]);
    deepEqual(controller.accessibleLocations(userB), [locationA, locationB]);
    deepEqual(controller.accessibleLocations(userC), []);
  });

  test('asyncExecuteAll', function() {
    var cnt = 0, success = false;
    function taskA(onSuccess) {
      cnt += 1;
      onSuccess();
    };
    function taskB(onSuccess) {
      cnt += 1;
      onSuccess();
    };
    function taskC(onSuccess) {
      cnt += 1;
      onSuccess();
    };
    function allDone() {
      success = true;
    };
    controller.asyncExecuteAll([taskA, taskB, taskC], allDone);
    deepEqual(cnt, 3);
    ok(success);
  });

  test('asyncExecuteAllTaskFailure', function() {
    var cnt = 0, success = false;
    function taskA(onSuccess) {
      cnt += 1;
      // This task fails (onSuccess is not invoked).
    };
    function taskB(onSuccess) {
      cnt += 1;
      onSuccess();
    };
    function taskC(onSuccess) {
      cnt += 1;
      onSuccess();
    };
    function allDone() {
      success = true;
    };
    controller.asyncExecuteAll([taskA, taskB, taskC], allDone);
    deepEqual(cnt, 3);
    // allDone should not be invoked.
    ok(!success);
  });

  module('Controller Ajax calls');

  test('getLocations', function() {
    var ajaxCallResult, callbackCalled;
    ajaxCallResult = {
      locations: [
        {
          path: '/foo',
          id: '1'
        },
        {
          path: '/bar',
          id: '2'
        }
      ]
    };
    mock_net.expectAjaxCall('GET', 'api/locations/', null, ajaxCallResult);
    callbackCalled = false;
    controller.getLocations(function() {
      callbackCalled = true;
    });
    deepEqual(controller.locations, ajaxCallResult.locations);
    ok(callbackCalled);
    mock_net.verify();
  });

  test('addLocation', function() {
    deepEqual(controller.locations, []);
    var newLocation = {id: '13', path: '/foo', allowedUsers: []};
    mock_net.expectAjaxCall('POST', 'api/locations/', {path: '/foo'},
                             newLocation);
    controller.addLocation('/foo');
    deepEqual(controller.locations, [newLocation]);
    mock_net.verify();
  });

  test('handledByAdmin', function() {
    controller.adminPath = '/wwwhisper/admin';
    ok(controller.handledByAdmin('/wwwhisper/admin/'));
    ok(controller.handledByAdmin('/wwwhisper/admin/foo/bar'));
    ok(!controller.handledByAdmin('/wwwhisper/admi'));
    ok(!controller.handledByAdmin('/admin'));
    ok(!controller.handledByAdmin('/admino'));
  });

  test('addLocation refuses to add sublocations to admin', function() {
    controller.adminPath = '/wwwhisper/admin';
    controller.addLocation('/wwwhisper/admin/api');
    deepEqual(controller.locations, []);
    ok(utils.startsWith(mock_ui.lastError,
                        'Adding sublocations to admin is not supported'))
    mock_net.verify();
  });

  test('removeLocation', function() {
    controller.locations = [{
      id: '13',
      path: '/foo',
      self: 'example.com/locations/13/',
      allowedUsers: []
    }];
    mock_net.expectAjaxCall(
      'DELETE', controller.locations[0].self, null, null);
    controller.removeLocation(controller.locations[0]);
    deepEqual(controller.locations, []);
    mock_net.verify();
  });

  test('getUsers', function() {
    var ajaxCallResult, callbackCalled;
    ajaxCallResult = {
      users: [
        {
          email: 'foo@example.com',
          id: '1'
        },
        {
          email: 'bar@example.com',
          id: '2'
        }
      ]
    };
    callbackCalled = false;
    mock_net.expectAjaxCall('GET', 'api/users/', null, ajaxCallResult);
    controller.getUsers(function() {
      callbackCalled = true;
    });
    deepEqual(controller.users, ajaxCallResult.users);
    ok(callbackCalled);
    mock_net.verify();
  });

  test('addUser', function() {
    var nextCallbackInvoked, newUser;
    deepEqual(controller.users, []);
    nextCallbackInvoked = false;
    newUser = {id: '13', email: 'foo@example.com'};
    mock_net.expectAjaxCall('POST', 'api/users/', {email: 'foo@example.com'},
                             newUser);
    controller.addUser('foo@example.com',
                      function(userArg) {
                        nextCallbackInvoked = true;
                        deepEqual(userArg, newUser);
                      });
    ok(nextCallbackInvoked);
    deepEqual(controller.users, [newUser]);
    mock_net.verify();
  });

  test('removeUser', function() {
    controller.users = [{
      id: '13',
      email: 'foo@example.com',
      self: 'example.com/users/13/'
    }];
    mock_net.expectAjaxCall('DELETE', controller.users[0].self, null, null);
    controller.removeUser(controller.users[0]);
    deepEqual(controller.users, []);
    mock_net.verify();
  });

  test('removeUser removes from location.allowedUsers list.', function() {
    var location, user;
    user = {
      id: '13',
      email: 'foo@example.com',
      self: 'example.com/users/13/'
    };
    location = {
      id: '17',
      path: '/bar',
      self: 'example.com/locations/13/',
      allowedUsers: [user]
    };
    controller.users.push(user);
    controller.locations.push(location);
    mock_net.expectAjaxCall('DELETE', controller.users[0].self, null, null);

    ok(controller.canAccess(user, location));
    controller.removeUser(controller.users[0]);
    ok(!controller.canAccess(user, location));

    deepEqual(location.allowedUsers, []);
    mock_net.verify();
  });

  test('grantAccess when user exists', function() {
    var location, user;
    user = {
      id: '17',
      email: 'foo@example.com',
      self: 'example.com/users/17/'
    };
    location = {
      id: '13',
      path: '/bar',
      self: 'example.com/locations/13/',
      allowedUsers: []
    };
    controller.users.push(user);
    controller.locations.push(location);
    mock_net.expectAjaxCall(
      'PUT', location.self + 'allowed-users/17/', null, user);

    ok(!controller.canAccess(user, location));
    controller.grantAccess(user.email, location);
    ok(controller.canAccess(user, location));

    deepEqual(controller.locations[0].allowedUsers, [user]);
    mock_net.verify();
  });

  test('grantAccess when user does not exist', function() {
    var location, user;
    user = {
      id: '17',
      email: 'foo@example.com',
      self: 'example.com/users/17/'
    };
    location = {
      id: '13',
      path: '/bar',
      self: 'example.com/locations/13/',
      allowedUsers: []
    };
    controller.locations.push(location);
    // User should first be added.
    mock_net.expectAjaxCall(
      'POST', 'api/users/', {email: 'foo@example.com'}, user);
    mock_net.expectAjaxCall(
      'PUT', location.self + 'allowed-users/17/', null, user);

    ok(!controller.canAccess(user, location));
    controller.grantAccess(user.email, location);
    ok(controller.canAccess(user, location));

    deepEqual(controller.locations[0].allowedUsers, [user]);
    deepEqual(controller.users, [user]);
    mock_net.verify();
  });

  test('grantAccess when user already can access location', function() {
    var location, user;
    user = {
      id: '17',
      email: 'foo@example.com',
      self: 'example.com/users/17/'
    };
    location = {
      id: '13',
      path: '/bar',
      self: 'example.com/locations/13/',
      allowedUsers: [user]
    };
    controller.users.push(user);
    controller.locations.push(location);

    ok(controller.canAccess(user, location));
    controller.grantAccess(user.email, location);
    ok(controller.canAccess(user, location));

    mock_net.verify();
  });

  test('revokeAccess', function() {
    var location, user;
    user = {
      id: '17',
      email: 'foo@example.com',
      self: 'example.com/users/17/'
    };
    location = {
      id: '13',
      path: '/bar',
      self: 'example.com/locations/13/',
      allowedUsers: [user]
    };
    controller.users.push(user);
    controller.locations.push(location);

    mock_net.expectAjaxCall(
      'DELETE', location.self + 'allowed-users/17/', null, null);

    ok(controller.canAccess(user, location));
    controller.revokeAccess(user, location);
    ok(!controller.canAccess(user, location));

    deepEqual(controller.locations[0].allowedUsers, []);
    mock_net.verify();
  });

  test('grantOpenAccess.', function() {
    var location, params;
    location = {
      id: '13',
      path: '/bar',
      self: 'example.com/locations/13/',
      allowedUsers: []
    };
    controller.locations.push(location);
    mock_net.expectAjaxCall(
      'PUT', location.self + 'open-access/', null, true);

    controller.grantOpenAccess(location);
    deepEqual(location.openAccess, true);
    mock_net.verify();
  });

  test('canAccess for open location.', function() {
    var location, params, user;
    user = {
      id: '17',
      email: 'foo@example.com',
      self: 'example.com/users/17/'
    };
    location = {
      id: '13',
      path: '/bar',
      self: 'example.com/locations/13/',
      allowedUsers: []
    };
    controller.users.push(user);
    controller.locations.push(location);

    mock_net.expectAjaxCall(
      'PUT', location.self + 'open-access/', null, null);

    ok(!controller.canAccess(user, location));
    controller.grantOpenAccess(location);
    ok(controller.canAccess(user, location));
    mock_net.verify();
  });

  test('revokeOpenAccess.', function() {
    var location;
    location = {
      id: '13',
      openAccess: {
        requireLogin: false
      },
      path: '/bar',
      self: 'example.com/locations/13/',
      allowedUsers: []
    };
    controller.locations.push(location);
    mock_net.expectAjaxCall(
      'DELETE', location.self + 'open-access/', null, null);

    controller.revokeOpenAccess(location);
    ok(!('openAccess' in location));
    mock_net.verify();
  });

  test('getAdminUser', function() {
    var ajaxCallResult, callbackCalled;
    ajaxCallResult = {
      email: 'foo@example.com'
    };
    callbackCalled = false;
    ok(controller.adminUserEmail === null);
    mock_net.expectAjaxCall(
      'GET', '/wwwhisper/auth/api/whoami/', null, ajaxCallResult);
    controller.getAdminUser(function() {
      callbackCalled = true;
    });
    deepEqual(controller.adminUserEmail, ajaxCallResult.email);
    ok(callbackCalled);
    mock_net.verify();
  });

  test('getAliases', function() {
    var ajaxCallResult, callbackCalled;
    ajaxCallResult = {
      aliases: [
        {
          url: 'https://example.org',
          id: '1'
        },
        {
          url: 'http://example.org',
          id: '2'
        }
      ]
    };
    callbackCalled = false;
    mock_net.expectAjaxCall('GET', 'api/aliases/', null, ajaxCallResult);
    controller.getAliases(function() {
      callbackCalled = true;
    });
    deepEqual(controller.aliases, ajaxCallResult.aliases);
    ok(callbackCalled);
    mock_net.verify();
  });

  test('addAlias', function() {
    deepEqual(controller.aliases, []);
    var newAlias = {id: '13', url: 'https://example.org'};
    mock_net.expectAjaxCall(
      'POST', 'api/aliases/', {url: 'https://example.org'}, newAlias);
    controller.addAlias('https://example.org');
    deepEqual(controller.aliases, [newAlias]);
    mock_net.verify();
  });

  test('removeAlias', function() {
    controller.aliases = [{
      id: '13',
      url: 'http://example.com',
      self: 'example.com/aliases/13/'
    }];
    mock_net.expectAjaxCall('DELETE', controller.aliases[0].self, null, null);
    controller.removeAlias(controller.aliases[0]);
    deepEqual(controller.aliases, []);
    mock_net.verify();
  });

  test('getSkin', function() {
    var ajaxCallResult, callbackCalled;
    ajaxCallResult = {
      'title': 'Foo',
      'header': 'Bar',
      'message': 'Baz',
      'branding': false
    };
    callbackCalled = false;
    mock_net.expectAjaxCall('GET', 'api/skin/', null, ajaxCallResult);
    controller.getSkin(function() {
      callbackCalled = true;
    });
    deepEqual(controller.skin, ajaxCallResult);
    ok(callbackCalled);
    mock_net.verify();
  });

  test('updateSkin', function() {
    var newSkin = {
      'title': 'Foo',
      'header': 'Bar',
      'message': 'Baz',
      'branding': false
    };
    mock_net.expectAjaxCall('PUT', 'api/skin/', newSkin, newSkin);
    controller.updateSkin(newSkin)
    deepEqual(controller.skin, newSkin);
    mock_net.verify();
  });

}());
