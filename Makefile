all:
	gcc -o netusse netusse.c utils.c -g

clean:
	@rm netusse
