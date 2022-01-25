NAME		=	ft_ssl

CC			=	gcc
CFLAGS		+=	-O3

INC_PATH	=	./includes/
INCLUDES	=	$(NAME).h
INCS		=	$(addprefix $(INC_PATH), $(INCLUDES))

SRC_PATH	=	./srcs/
SRC			=	$(NAME).c \
				t_hash.c \
				bitwise.c \
				io/parsing.c \
				io/padding.c \
				io/output.c \
				utils/libft.c \
				utils/verbose.c \
				utils/errors.c \
				algorithms/sha256.c \
				algorithms/md5.c \
				algorithms/pbkdf2.c \
				algorithms/des.c \
				algorithms/base64.c

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
	@mkdir $(BIN_PATH) || true
	@mkdir $(BIN_PATH)/algorithms || true
	@mkdir $(BIN_PATH)/io || true
	@mkdir $(BIN_PATH)/utils || true

clean:
	@rm -rf $(BIN_PATH)
	@echo "[CLEANING $(NAME) BINARIES]"

fclean: clean
	@rm -f $(NAME)
	@echo "[REMOVING \"$(NAME)\"]"

re: fclean all
