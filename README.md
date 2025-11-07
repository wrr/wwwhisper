Access control for Heroku hosted apps
-------------------------------------

wwwhisper is a low latency HTTP reverse proxy, which allows you to
easily add verified email based authentication and authorization to
Heroku-hosted web applications.

The wwwhisper reverse proxy is language, framework and application
independent, it can forward requests and add authorization to any HTTP
server or web app.

The proxy is developed with low-latency as the primary concern.  Auth
decisions must be made before each request is passed to the app, so
any latency introduced by the auth layer increased the total
processing time of each HTTP request. For this reason, the wwwhisper
proxy heavily caches auth data, and most incoming requests are
authorized fully locally without contacting the wwwhisper backend.
The cache has mechanisms for quickly detecting and evicting stalled
data.

Setup
-----
To enable wwwhisper for your Heroku-hosted web application, follow
the [Heroku Dev Center instructions](https://devcenter.heroku.com/articles/wwwhisper).

Quick tour
-----------

A user who visits a wwwhisper-protected site is presented with a
login prompt:

![Login prompt](https://raw.github.com/wrr/wrr.github.io/main/wwwhisper-screens/wwwhisper-login.png)

The `Request a login link` button sends a link with an email
verification token to the provided email address.

After the link is clicked, wwwhisper verifies whether the user is
authorized to access the URL. If this is the case, the user is taken
to the site.

By default, wwwhisper inserts a small overlay in the lower-right
corner of each protected HTML document. The overlay displays the
current user's email a `Sign out` button:

![Overlay](https://raw.github.com/wrr/wrr.github.io/main/wwwhisper-screens/wwwhisper-overlay.png)

Finally, the admin application allows to easily grant or revoke access:

![Admin](https://raw.github.com/wrr/wrr.github.io/main/wwwhisper-screens/wwwhisper-admin.png)


Compiling and running
---------------------
*Note: on Heroku you don't need to compile and run wwwhisper directly,
just follow the Heroku Dev Center instructions to add a buildpack to
your app.*

If you subscribe to the wwwhisper add-on, you can run the wwwhisper
proxy locally or in front of any HTTP service, even outside of
Heroku. To do it, compile wwwhisper:

```
make
```

Obtain the `WWWHISPER_URL` variable from Heroku and make it available to wwwhisper:

```
export WWWHISPER_URL=`heroku config:get WWWHISPER_URL`
```

Run wwwhisper:

```
./wwwhisper -listen 8080 -proxyto 8000
```

Buildpacks
----------
The code in this repository is packaged and made available as a
[Heroku Buildpack](
https://github.com/wwwhisper-auth/wwwhisper-heroku-buildpack) for the
Heroku Common Runtime and Cedar Private Spaces, and as a [Cloud Native
Buildpack](https://github.com/wwwhisper-auth/wwwhisper-cnb) for the
Heroku Fir Private Spaces.

Alternatives
------------
wwwhisper authorization was originally provided as [Ruby Rack
middleware](https://rubygems.org/gems/rack-wwwhisper) and [Node.js
Connect middleware](https://www.npmjs.com/package/connect-wwwhisper).
These middlewares are still supported and can be used for Ruby and
Node apps if you prefer middleware based, same process integration,
rather than running a separate proxy process in front of the app.


Project history
---------------

* wwwhisper was launched in 2012 as a non-commercial open source
  project for authenticating/authorizing requests to web apps.

* The development of the project was motivated by the introduction of
  [Mozilla Persona](https://en.wikipedia.org/wiki/Mozilla_Persona) a
  decentralized authentication system that wwwhisper used.

* At that time, wwwhisper was available as a Django-based backend with
  which nginx communicated using auth-request module.

* In those pre-Docker era, running and configuring a third-party
  backend like wwwhisper was cumbersome. wwwhisper tried to simplify
  things as much as possible with installation scripts, but that did
  not help with the adoption. People liked the project idea, but not
  many actually used wwwhisper.

* In 2013, a commercial wwwhisper Heroku add-on was launched. The
  managed backend provided by the add-on solved the problem of
  installation complexity, and the add-on has seen much better
  adoption than the free, open-source wwwhisper.

* The integration with the add-on was provided as Ruby Rack
  middleware, thus the add-on was available for Ruby apps only.

* In 2014, a Node.js Connect middleware was created and the wwwhisper
  add-on became available for Node apps.

* In 2016, Mozilla shut down the Persona project. To continue
  operations, the wwwhisper add-on switched to email-based login
  tokens. The open source version of wwwhisper was never extended to
  support the tokens, no one complained and further development of
  open source wwwhisper backend was halted.

* In 2023, an nginx based wwwhisper Heroku buildpack was launched which
  used the nginx auth-request module. As a generic HTTP reverse proxy
  it allowed to use wwwhisper add-on with any language and framework,
  not just Ruby and Node.

* In 2025, the wwwhisper Heroku buildpack was switched from using
  nginx to a custom Go-based proxy (this repository). This change
  enabled authentication data caching, which is crucial for
  efficiently running wwwhisper-protected apps at any location in the
  world, not just near to the wwwhisper managed backends (EU and US).
