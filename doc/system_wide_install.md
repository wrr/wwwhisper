### Make sure required packages are installed.

    sudo apt-get install git python python-dev python-virtualenv libssl-dev libpcre3-dev;

### Get, compile and install nginx.
     # Download and unpack the latest stable nginx.
    mkdir -p ~/src; cd ~/src;
    NGINX_VERSION='nginx-1.4.4';
    wget http://nginx.org/download/${NGINX_VERSION}.tar.gz;
    tar xvfz ${NGINX_VERSION}.tar.gz;
    cd ${NGINX_VERSION};
     # Get auth-request module.
    git clone https://github.com/PiotrSikora/ngx_http_auth_request_module.git;
     # Configure nginx. If your site needs any additional modules add them here.
    ./configure --add-module=./ngx_http_auth_request_module/ \
      --with-http_ssl_module --with-http_sub_module --user=www-data \
      --group=www-data --prefix=/usr/local/nginx/ --sbin-path=/usr/local/sbin
     # Compile and install nginx.
    make; sudo make install;

### Install wwwhisper.
     # Add a system user to run the wwwhisper service.
    sudo adduser --system --ingroup www-data wwwhisper;
     # Become the user.
    cd ~wwwhisper; sudo su --shell /bin/bash wwwhisper;
     # Clone wwwhisper project to the wwwhisper home dir.
    git clone https://github.com/wrr/wwwhisper.git .;
     # Create and activate virtual environment.
    virtualenv venv;
    source venv/bin/activate;
     # Install required packages in the virtual environment.
    pip install -r ./requirements.txt;
     # Generate configurations files for a site to protect. You need to
     # specify your email as admin_email to be able to access the
     # admin web application. This step can be later repeated to enable
     # protection for multiple sites.
    ./add_site_config.py --site-url  http[s]://your.domain[:port] --admin-email your@email;

### Configure nginx.
Edit /usr/local/nginx/conf/nginx.conf and enable wwwhisper
authorization. In the server section put:

    set $wwwhisper_root /home/wwwhisper/;
    set $wwwhisper_site_socket unix:$wwwhisper_root/sites/$scheme.$server_name.$server_port/uwsgi.sock;
    include /home/wwwhisper/nginx/wwwhisper.conf;

See [a sample configuration
file](https://github.com/wrr/wwwhisper/blob/master/nginx/sample_nginx.conf)
for a detailed explanation of wwwhisper related configuration
directives.

### Configure supervisord.

Supervisord can be used to automatically start nginx and uwsgi managed
wwwhisper process. Alternatively you can use a little harder to
configure [init.d scripts](http://wiki.nginx.org/Nginx-init-ubuntu).

     sudo apt-get install supervisor;

 Edit /etc/supervisor/supervisord.conf and extend existing include directive to include `/home/wwwhisper/sites/*/supervisor/site.conf` and `/home/wwwhisper/nginx/supervisor.conf`. The directive should now look something like:

    [include]
    files = /etc/supervisor/conf.d/*.conf /home/wwwhisper/sites/*/supervisor/site.conf \
            /home/wwwhisper/nginx/supervisor.conf

Note that supervisord does not allow multiple include directives, you need to extend the existing one.

Finally, restart the supervisor

    sudo /etc/init.d/supervisor stop;
    sleep 20;
    sudo /etc/init.d/supervisor start;

Point your browser to http[s]://your.site.address/admin, you should be
presented with a login page. Sign in with the admin email and use the
admin application to define which locations can be accessed by which
visitors.
