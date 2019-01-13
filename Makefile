CFLAGS += -Wall -Werror -Wextra -Iinclude
LDFLAGS += 

CFLAGS += `pkg-config --cflags libsodium`
LDFLAGS += `pkg-config --libs libsodium`

NAME = unilink

SRCS = src/main.c src/server.c src/peerinfo.c src/net.c
OBJS = ${SRCS:.c=.o}

$(NAME): $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o $(NAME)

all: $(NAME)

clean:
	$(RM) $(OBJS)

fclean: clean
	$(RM) $(NAME)

.PHONY: all clean fclean
