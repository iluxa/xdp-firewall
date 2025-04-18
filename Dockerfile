FROM gilyav/ebpf-build AS builder

WORKDIR /app

COPY . .

RUN make

FROM busybox

COPY --from=builder ["/app/xdpfw", "/usr/sbin"]
COPY --from=builder ["/app/xdpfw-cli", "/usr/bin"]