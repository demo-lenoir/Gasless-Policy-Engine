FROM golang:1.27.1-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -buildvcs=false -ldflags='-s -w' -o /gasless ./cmd/gasless

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /gasless /gasless
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/gasless"]
