FROM docker/compose-bin:latest AS compose

FROM docker:27-cli

COPY --from=compose /docker-compose /usr/local/libexec/docker/cli-plugins/docker-compose
