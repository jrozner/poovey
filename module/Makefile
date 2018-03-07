CFLAGS = -fPIC -DPIC -shared -rdynamic

all:
	cc frozen.c pam_poovey.c -o pam_poovey.so $(CFLAGS)

clean:
	rm pam_poovey.so