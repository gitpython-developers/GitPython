#
# Contributed by: James E. King III (@jeking3) <jking@apache.org>
#
# This Dockerfile creates an Ubuntu Xenial build environment
# that can run the same test suite as Travis CI.
#

FROM ubuntu:xenial
MAINTAINER James E. King III <jking@apache.org>
ENV CONTAINER_USER=user
ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      add-apt-key \
      apt \
      apt-transport-https \
      apt-utils \
      ca-certificates \
      curl \
      git \
      net-tools \
      openssh-client \
      sudo \
      vim \
      wget

RUN add-apt-key -v 6A755776 -k keyserver.ubuntu.com && \
    add-apt-key -v E1DF1F24 -k keyserver.ubuntu.com && \
    echo "deb http://ppa.launchpad.net/git-core/ppa/ubuntu xenial main" >> /etc/apt/sources.list && \
    echo "deb http://ppa.launchpad.net/deadsnakes/ppa/ubuntu xenial main" >> /etc/apt/sources.list && \
    apt-get update && \
    apt-get install -y --install-recommends git python2.7 python3.4 python3.5 python3.6 python3.7 && \
    update-alternatives --install /usr/bin/python3 python3 /usr/bin/python2.7 27 && \
    update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.4 34 && \
    update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.5 35 && \
    update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.6 36 && \
    update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.7 37

RUN curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py && \
    python3 get-pip.py && \
    pip3 install tox

# Clean up
RUN rm -rf /var/cache/apt/* && \
    rm -rf /var/lib/apt/lists/* && \
    rm -rf /tmp/* && \
    rm -rf /var/tmp/*

#################################################################
# Build as a regular user
# Credit: https://github.com/delcypher/docker-ubuntu-cxx-dev/blob/master/Dockerfile
# License: None specified at time of import
# Add non-root user for container but give it sudo access.
# Password is the same as the username
RUN useradd -m ${CONTAINER_USER} && \
    echo ${CONTAINER_USER}:${CONTAINER_USER} | chpasswd && \
    echo "${CONTAINER_USER}  ALL=(root) ALL" >> /etc/sudoers
RUN chsh --shell /bin/bash ${CONTAINER_USER}
USER ${CONTAINER_USER}
#################################################################

# The test suite will not tolerate running against a branch that isn't "master", so
# check out the project to a well-known location that can be used by the test suite.
# This has the added benefit of protecting the local repo fed into the container
# as a volume from getting destroyed by a bug exposed by the test suite. :)
ENV TRAVIS=ON
RUN git clone --recursive https://github.com/gitpython-developers/GitPython.git /home/${CONTAINER_USER}/testrepo && \
    cd /home/${CONTAINER_USER}/testrepo && \
    ./init-tests-after-clone.sh
ENV GIT_PYTHON_TEST_GIT_REPO_BASE=/home/${CONTAINER_USER}/testrepo
ENV TRAVIS=

# Ensure any local pip installations get on the path
ENV PATH=/home/${CONTAINER_USER}/.local/bin:${PATH}

# Set the global default git user to be someone non-descript
RUN git config --global user.email ci@gitpython.org && \
    git config --global user.name "GitPython CI User"

