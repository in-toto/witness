FROM scratch

ADD witness /witness

ENTRYPOINT ["/witness"]

