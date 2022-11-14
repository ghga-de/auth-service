# Copyright 2021 - 2022 Universität Tübingen, DKFZ and EMBL
# for the German Human Genome-Phenome Archive (GHGA)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM python:3.10.5-alpine3.16

COPY . /service
WORKDIR /service

RUN apk update && apk upgrade
RUN apk add --no-cache gcc
RUN apk add --update alpine-sdk
# Security patch toss busybox
RUN apk upgrade busybox --repository=http://dl-cdn.alpinelinux.org/alpine/edge/main

RUN pip install .

# create new user and execute as that user
RUN addgroup -S appuser && adduser -S appuser -G appuser
USER appuser
WORKDIR /home/appuser

ENV PYTHONUNBUFFERED=1

# Please adapt to package name:
ENTRYPOINT ["auth-service"]
