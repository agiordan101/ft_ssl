NAME		=	ft_ssl

CC			=	gcc
CFLAGS		+=	-O3

INC_PATH	=	./includes/
INCLUDES	=	$(NAME).h
INCS		=	$(addprefix $(INC_PATH), $(INCLUDES))

SRC_PATH	=	./srcs/
SRC			=	$(NAME).c \
				t_hash.c \
				io/output.c \
				io/errors.c \
				io/parsing.c \
				io/padding.c \
				io/verbose.c \
				utils/libft.c \
				calculations/maths.c \
				calculations/bitwise.c \
				algorithms/prime.c \
				algorithms/pbkdf2.c \
				algorithms/md/sha256.c \
				algorithms/md/md5.c \
				algorithms/ciphers/des.c \
				algorithms/ciphers/base64.c \
				algorithms/standard/genrsa.c

BIN_PATH	=	./bins/
BIN			=	$(SRC:.c=.o)
BINS		=	$(addprefix $(BIN_PATH), $(BIN))

.PHONY: all clean fclean re dirs

#__________RULES__________#

all: dirs $(NAME)

$(NAME): $(BINS)

	@$(CC) $(CFLAGS) -o $@ $^ -I $(INC_PATH) -lm
	@echo "[EXECUTABLE \"$(NAME)\" READY]\n"

$(BIN_PATH)%.o: $(SRC_PATH)%.c $(INCS)

	@$(CC) $(CFLAGS) -I $(INC_PATH) -o $@ -c $< && echo " \c"

dirs:
	@mkdir -p $(BIN_PATH)/io || true
	@mkdir -p $(BIN_PATH)/utils || true
	@mkdir -p $(BIN_PATH)/calculations || true
	@mkdir -p $(BIN_PATH)/algorithms/md || true
	@mkdir -p $(BIN_PATH)/algorithms/ciphers || true
	@mkdir -p $(BIN_PATH)/algorithms/standard || true

clean:
	@rm -rf $(BIN_PATH)
	@echo "[CLEANING $(NAME) BINARIES]"

fclean: clean
	@rm -f $(NAME)
	@echo "[REMOVING \"$(NAME)\"]"

re: fclean all
