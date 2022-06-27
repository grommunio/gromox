#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <unistd.h>
#include <libHX/io.h>
#include <libHX/misc.h>
#include <sys/random.h>
#include <gromox/defs.h>
#include <gromox/lzxpress.hpp>

using namespace gromox;

int main(int argc, char **argv)
{
	bool decompress = false, randomtest = false;
	int c;
	while ((c = getopt(argc, argv, "Rcdk")) >= 0) {
		if (c == 'd')
			decompress = true;
		if (c == 'R')
			randomtest = true;
	}
	uint8_t outbuf[0x1000];
	if (randomtest) {
		char b1[1], b2[512];
		size_t z = 0;
		while (1) {
			getrandom(b1, std::size(b1), 0);
			auto complen = lzxpress_compress(b1, std::size(b1), b2);
			auto ucomplen = lzxpress_decompress(b2, complen, outbuf, std::size(outbuf));
			if (ucomplen != std::size(b1)) {
				fprintf(stderr, "Failed input (%zu):\n", ++z);
				HX_hexdump(stderr, b1, std::size(b1));
				HX_hexdump(stderr, b2, complen);
				HX_hexdump(stderr, outbuf, ucomplen);
				return EXIT_FAILURE;
			}
		}
		return EXIT_SUCCESS;
	}
	size_t slurp_len = 0;
	std::unique_ptr<char[], stdlib_delete> slurp_data(HX_slurp_fd(STDIN_FILENO, &slurp_len));
	if (slurp_data == nullptr) {
		fprintf(stderr, "Unable to read from stdin: %s\n", strerror(errno));
		return EXIT_FAILURE;
	}
	uint32_t ret = decompress ?
	               lzxpress_decompress(slurp_data.get(), slurp_len,
	               outbuf, std::size(outbuf)) :
	               lzxpress_compress(slurp_data.get(), slurp_len, outbuf);
	if (ret == 0) {
		fprintf(stderr, "Something went wrong\n");
		return EXIT_FAILURE;
	}
	if (HXio_fullwrite(STDOUT_FILENO, outbuf, ret) < 0)
		return EXIT_FAILURE;
	return EXIT_SUCCESS;
}
