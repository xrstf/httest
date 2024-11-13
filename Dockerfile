# SPDX-FileCopyrightText: 2024 Christoph Mewes
# SPDX-License-Identifier: MIT

FROM gcr.io/distroless/static-debian12:nonroot

ENTRYPOINT ["httest"]

COPY httest /usr/local/bin/
