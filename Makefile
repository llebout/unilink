CFLAGS += -Wall -Werror -Wextra -Iinclude
LDFLAGS += 

CFLAGS += `pkg-config --cflags libsodium`
LDFLAGS += `pkg-config --libs libsodium`

NAME = unilink

SRCS = src/main.c
OBJS = src/main.o

$(NAME): $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o $(NAME)

all: $(NAME)

clean:
	$(RM) $(OBJS)

fclean: clean
	$(RM) $(NAME)

.PHONY: all clean fclean
