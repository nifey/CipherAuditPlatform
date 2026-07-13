FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    vim \
    python3 \
    python3-pip \
    python3-venv \
    build-essential \
    flex \
    bison \
    libgmp-dev \
    libmpfr-dev \
    libmpc-dev \
    libwine-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

#
# Custom GCC
#
RUN mkdir -p /opt/custom-gcc
COPY CipherAuditPlatform/zeroisation/custom-gcc/ /opt/custom-gcc/
ENV PATH=/opt/custom-gcc/bin:$PATH

#
# GNUZero plugin
#
RUN mkdir -p /opt/gnuzero
COPY CipherAuditPlatform/zeroisation/gnuzero/build_custom/libscrub.so \
    /opt/gnuzero/libscrub.so

#
# CipherAuditPlatform
#
COPY CipherAuditPlatform/zeroisation /opt/CipherAuditPlatform/zeroisation

# Juliet scrub.h fix
RUN ln -sf \
    /opt/CipherAuditPlatform/zeroisation/gnuzero/scrub.h \
    /opt/CipherAuditPlatform/zeroisation/juliet-testsuite-adapted/testcasesupport/scrub.h

WORKDIR /opt/CipherAuditPlatform


CMD ["/bin/bash"]