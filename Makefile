all:
	gcc -o netusse netusse.c utils.c -O3

clean:
	@rm netusse
