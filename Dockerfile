FROM scratch

ARG BINARY_PATH
ADD ${BINARY_PATH} /witness

ENTRYPOINT ["/witness"]