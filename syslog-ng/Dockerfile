# Official syslog-ng image from One Identity (the upstream syslog-ng project).
# Debian-based, current stable release, includes the http() module + jemalloc.
# https://github.com/syslog-ng/syslog-ng  (image: docker.io/balabit/syslog-ng)
FROM balabit/syslog-ng:latest

# Disk-buffer + fallback dirs (ca-certificates ships in the base image for TLS).
RUN mkdir -p /var/lib/syslog-ng/dp-queue /var/log/syslog-ng

COPY syslog-ng.conf /etc/syslog-ng/syslog-ng.conf

EXPOSE 514/udp 601/tcp

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD syslog-ng-ctl stats >/dev/null 2>&1 || exit 1

# The upstream image's own entrypoint.sh (/usr/local/bin/entrypoint.sh) does
# `echo; set; echo` before exec'ing syslog-ng -- a debug leftover that dumps
# every shell/env var, including HEC_TOKEN, into `docker logs` in plaintext.
# Reimplement its actual behavior (jemalloc preload + exec syslog-ng as PID 1
# for clean signal handling) without that dump. --no-caps is appended because
# the container runs unprivileged; the config is read from the default path.
ENTRYPOINT ["/bin/bash", "-c", "unset LD_PRELOAD; export LD_PRELOAD=\"/usr/lib/$(uname -m)-linux-gnu/libjemalloc.so.2\"; exec /usr/sbin/syslog-ng -F \"$@\"", "--"]
CMD ["--no-caps", "-f", "/etc/syslog-ng/syslog-ng.conf"]
