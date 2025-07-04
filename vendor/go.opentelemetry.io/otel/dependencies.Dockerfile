# This is a renovate-friendly source of Docker images.
FROM python:3.13.3-slim-bullseye@sha256:9e3f9243e06fd68eb9519074b49878eda20ad39a855fac51aaffb741de20726e AS python
FROM otel/weaver:v0.16.0@sha256:ee6eefd8cd8f4d2cfb7763b8a0fd613cfdf7dfbfda97e0e9b49d1a00dd01f7d6 AS weaver
FROM avtodev/markdown-lint:v1@sha256:6aeedc2f49138ce7a1cd0adffc1b1c0321b841dc2102408967d9301c031949ee AS markdown
