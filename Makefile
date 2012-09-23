ndp-proxy: main.c
	$(CC) -o $@ $^

clean:
	@rm ndp-proxy 2>/dev/null || true
