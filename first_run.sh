#/bin/sh!
[ ! -d "/path/to/dir" ] && mkdir /usr/lib/nps
SSL_VER=`openssl version | awk '{print $2}'`
cp *.so.${SSL_VER} /usr/lib/nps/.
