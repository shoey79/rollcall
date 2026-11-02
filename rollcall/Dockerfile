ARG BUILD_FROM
FROM ${BUILD_FROM}
ARG BUILD_VERSION
ENV PM_VERSION=${BUILD_VERSION}

RUN apk add --no-cache python3 py3-aiohttp iputils tzdata

COPY app /app
COPY run.sh /run.sh
RUN chmod a+x /run.sh

CMD [ "/run.sh" ]
