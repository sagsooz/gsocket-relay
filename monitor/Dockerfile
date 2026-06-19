FROM ubuntu:latest

COPY heartbeat.sh funcs /
COPY gsocket_latest_all.deb /tmp
RUN apt update -y && \
	apt install -y --no-install-recommends \
	openssl && \
	apt clean && \
	rm -rf /var/lib/apt/lists/ && \
	dpkg -i --ignore-depends sshfs /tmp/gsocket_latest_all.deb && \
	echo DONE

ENTRYPOINT ["/heartbeat.sh"]
CMD ["bh1", "bh2", "bh3"]
