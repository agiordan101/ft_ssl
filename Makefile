NAME		=	ft_ssl

CC			=	gcc
CFLAGS		+=	-O3

INC_PATH	=	./includes/
INCLUDES	=	$(NAME).h
INCS		=	$(addprefix $(INC_PATH), $(INCLUDES))

SRC_PATH	=	./srcs/
SRC			=	$(NAME).c \
				t_hash.c \
				io/parsing.c \
				io/usages.c \
				io/errors.c \
				io/output.c \
				utils/libft.c \
				calculations/maths.c \
				calculations/bitwise.c \
				algorithms/padding.c \
				algorithms/md/sha256.c \
				algorithms/md/md5.c \
				algorithms/ciphers/des.c \
				algorithms/ciphers/base64.c \
				algorithms/ciphers/pbkdf2.c \
				algorithms/standard/genprime.c \
				algorithms/standard/isprime.c \
				algorithms/standard/rsa.c \
				algorithms/standard/genrsa.c \
				algorithms/standard/rsautl.c \
				algorithms/standard/rsa_cryptosystem.c \
				algorithms/standard/formats/DER.c \
				algorithms/standard/formats/PEM.c

# SRC += io/verbose.c

BIN_PATH	=	./bins/
BIN			=	$(SRC:.c=.o)
BINS		=	$(addprefix $(BIN_PATH), $(BIN))

.PHONY: all clean fclean re dirs

#__________RULES__________#

all: dirs $(NAME)

$(NAME): $(BINS)

	@$(CC) $(CFLAGS) -o $@ $^ -I $(INC_PATH) -lm
	@echo "\n[All \"$(NAME)\" binaries successfully create]"
	@echo "[Executable \"$(NAME)\" successfully compile]\n"

$(BIN_PATH)%.o: $(SRC_PATH)%.c $(INCS)

	@$(CC) $(CFLAGS) -I $(INC_PATH) -o $@ -c $< && echo "#\c"

dirs:
	@mkdir -p $(BIN_PATH)/io || true
	@mkdir -p $(BIN_PATH)/utils || true
	@mkdir -p $(BIN_PATH)/calculations || true
	@mkdir -p $(BIN_PATH)/algorithms/md || true
	@mkdir -p $(BIN_PATH)/algorithms/ciphers || true
	@mkdir -p $(BIN_PATH)/algorithms/standard || true
	@mkdir -p $(BIN_PATH)/algorithms/standard/formats || true

clean:
	@rm -rf $(BIN_PATH)
	@echo "[Removing $(NAME) binaries]"

fclean: clean
	@rm -f $(NAME)
	@echo "[Removing \"$(NAME)\" executable]"

test: all
	@sh unitests_ft_ssl.sh Makefile || echo "Unitests script 'unitests_ft_ssl.sh' not found"
	# @sh unitests_ft_ssl.sh ft_ssl || echo "Unitests script 'unitests_ft_ssl.sh' not found"

re: fclean all  



