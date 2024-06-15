FROM    127.0.0.1:5000/homed-service:latest
ARG     TARGETARCH
RUN     mkdir /etc/homed
RUN     ln -s /data/homed-cloud.conf /etc/homed/homed-cloud.conf
RUN     ln -s /data/homed.log /var/log/homed.log
COPY    homed-cloud-$TARGETARCH /usr/bin/homed-cloud
CMD     ["/usr/bin/homed-cloud"]
