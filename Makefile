CC_OPTIONS := 
LD_OPTIONS := -lpcap

ndp-proxy: main.c
	$(CC) $(CC_OPTIONS) -o $@ $^ $(LD_OPTIONS)

clean:
	@rm ndp-proxy 2>/dev/null || true
