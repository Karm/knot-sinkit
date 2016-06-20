FROM fedora:23
MAINTAINER Michal Karm Babacek <karm@email.cz>

# Environment
ENV PKGS_AUX automake autoconf gcc git findutils which patch libtool pkgconfig \
    gnutls-devel jansson-devel userspace-rcu-devel libcurl-devel libcmocka-devel knot-devel gmp-devel nettle-devel hiredis-devel libmemcached-devel

ENV PKGS luajit luajit-devel libuv libuv-devel gnutls jansson bash libcurl nettle gmp knot knot-libs hiredis libmemcached supervisor

ENV PKG_CONFIG_PATH /usr/bin/pkg-config
ENV CFLAGS -O2 -ftree-vectorize -fstack-protector -g
ENV LDFLAGS -Wl,--as-needed

# Expose port
EXPOSE 53/tcp
EXPOSE 53/udp

# Select entrypoint
WORKDIR /data

# Configure a user Knot switches to
RUN adduser kresd -M -s /sbin/nologin && \
    chown kresd /data/ -R && \
    chgrp kresd /data/ -R && \
    chmod g+s /data

# Sinkit sources
COPY ["modules/sinkit/*", \
      "LICENSE",          \
      "/tmp/sinkit/"]
COPY ["modules/modules.mk.patch", \
      "etc/config.sinkit",        \
      "/tmp/"]

    # Update system and install packages 
RUN dnf -y update && \
    dnf -y install ${PKGS} ${PKGS_AUX} && \
    git clone https://gitlab.labs.nic.cz/knot/resolver.git /tmp/build && \
    cd /tmp/build && \
    # Add sinkit module
    cp /tmp/sinkit modules/sinkit -R && \
    patch modules/modules.mk -i /tmp/modules.mk.patch && \
    # Make
    #./scripts/bootstrap-depends.sh /usr/local && \
    make -j4 install && \
    # Add sinkit config
    cp /tmp/config.sinkit /usr/local/etc/kresd/config.sinkit && \
    # Trim down the image
#   dnf -y remove ${PKGS_AUX} && \
    dnf clean all && \
    rm -rf /tmp/build

# TODO: Shouldn't be needed. ld?
ENV LD_LIBRARY_PATH=/usr/local/lib/:/usr/local/lib/kdns_modules/

# Supervisor
ADD supervisord.conf /etc/supervisor/conf.d/supervisord.conf

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf", "-n"]




