FROM itsafeaturemythic/mythic_python_base:latest

RUN apt-get update && apt-get install -y \
    curl xz-utils mingw-w64 \
    && rm -rf /var/lib/apt/lists/*

ENV NIM_VERSION=2.0.4
RUN curl -L https://nim-lang.org/download/nim-${NIM_VERSION}-linux_x64.tar.xz -o /tmp/nim.tar.xz \
    && tar -xf /tmp/nim.tar.xz -C /opt \
    && mv /opt/nim-${NIM_VERSION} /opt/nim \
    && rm /tmp/nim.tar.xz

ENV PATH="/opt/nim/bin:/root/.nimble/bin:${PATH}"

RUN nimble install winim -y

WORKDIR /Mythic/
CMD ["python3", "main.py"]
