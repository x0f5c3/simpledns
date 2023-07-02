FROM docker.io/library/rust as BUILDER
WORKDIR /project
COPY . /project/
RUN cargo build --release

FROM docker.io/library/rust
WORKDIR /application
COPY --from=BUILDER /project/target/release/simpledns /application/simpledns
ENTRYPOINT ["/application/simpledns"]
