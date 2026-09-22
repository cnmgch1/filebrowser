## Multistage build: First stage fetches dependencies
FROM alpine:3.23 AS fetcher

# Install and copy ca-certificates, mailcap, and tini-static; download JSON.sh.
#
# wget is requested explicitly instead of relying on the BusyBox applet: BusyBox
# wget does not tunnel HTTPS through an HTTP proxy — it never sends CONNECT, so
# the proxy answers 503 and the build dies on the JSON.sh fetch. That is exactly
# the network this image is often built on, where a proxy is the only way out.
RUN apk update && \
    apk --no-cache add ca-certificates mailcap tini-static wget && \
    wget -O /JSON.sh https://raw.githubusercontent.com/dominictarr/JSON.sh/0d5e5c77365f63809bf6e77ef44a1f34b0e05840/JSON.sh

# Stage the binary, made executable, from here rather than from the build
# context.
#
# `filebrowser` is a build-context artifact, and on Windows — where it is often
# assembled — the Go toolchain leaves no execute bit, tar records 0644, and
# Docker carries that mode into the image. The container then dies with
# "exec /bin/filebrowser: permission denied". Something has to fix the mode.
#
# Doing it in the final image would be wasteful: a chmod changes the file's
# metadata, so the layer holding it has to contain the whole 35 MB again, and
# the image ends up twice the size. COPY --chmod would avoid that but needs
# BuildKit, which is not always present. Routing through this stage gets the
# mode for free — these layers are discarded, and the final COPY records the
# mode it finds alongside the file.
COPY filebrowser /staging/filebrowser
RUN chmod 0755 /staging/filebrowser

## Second stage: Use lightweight BusyBox image for final runtime environment
FROM busybox:1.37.0-musl

# Define non-root user UID and GID
ENV UID=1000
ENV GID=1000

# Create user group and user
RUN addgroup -g $GID user && \
    adduser -D -u $UID -G user user

# Copy binary, scripts, and configurations into image with proper ownership
COPY --chown=user:user --from=fetcher /staging/filebrowser /bin/filebrowser
COPY --chown=user:user docker/common/ /
COPY --chown=user:user docker/alpine/ /
COPY --chown=user:user --from=fetcher /sbin/tini-static /bin/tini
COPY --from=fetcher /JSON.sh /JSON.sh
COPY --from=fetcher /etc/ca-certificates.conf /etc/ca-certificates.conf
COPY --from=fetcher /etc/ca-certificates /etc/ca-certificates
COPY --from=fetcher /etc/mime.types /etc/mime.types
COPY --from=fetcher /etc/ssl /etc/ssl

# Create the data directories, then make sure the helper scripts are ones the
# kernel can actually dispatch to.
#
# A script checked out with CRLF has a shebang of "#!/bin/sh\r", which names an
# interpreter that does not exist. The kernel reports that as "No such file or
# directory" — about a file that is sitting right there — which sends you looking
# in entirely the wrong place.
#
# It cannot be prevented at the checkout end: on Windows core.autocrlf=true is
# the installer default and it overrides the eol=lf attribute, so a fresh clone
# still gets CRLF. Fixing it here is the one place that works for every checkout.
# These files are small, so re-adding them to this layer costs nothing.
RUN mkdir -p /config /database /srv && \
    chown -R user:user /config /database /srv && \
    sed -i 's/\r$//' /init.sh /healthcheck.sh && \
    chmod +x /init.sh /healthcheck.sh

# Define healthcheck script
HEALTHCHECK --start-period=2s --interval=5s --timeout=3s CMD /healthcheck.sh

# Set the user, volumes and exposed ports
USER user

VOLUME /srv /config /database

EXPOSE 80

ENTRYPOINT [ "tini", "--", "/init.sh" ]
