int main(int argc, char** argv) {
	if (argc != 2) {
		return 666;
	}
	char* num = argv[1];
	char digit;
	unsigned int total = 0;

	unsigned char i = 0;
	while (num[i] != '\0') {
		digit = num[i] - '0';
		total *= 10;
		total += digit;
		i++;
	}
	return total;
}
