FROM golang:stretch

WORKDIR /go/src/github.com/PolarGeospatialCenter/k8s-policy
COPY cmd/ ./cmd/
COPY pkg/ ./pkg/
COPY Gopkg.toml Gopkg.lock ./

RUN apt-get install -y git make curl
RUN curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh
RUN dep ensure -v -vendor-only
RUN go build  -o /bin/k8s-policy ./cmd/k8s-policy

FROM scratch
COPY --from=0 /bin/k8s-policy /bin/k8s-policy
CMD /bin/k8s-policy
